<?php
/**
 * Vulnerability data: the chosen source, and the Wordfence Intelligence feed.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Front for the vulnerability data the scanner reads. WPVulnerability (no
 * account needed) is the default source; a site that stores its own Wordfence
 * Intelligence token can use the Wordfence feed instead. For Wordfence this
 * class fetches the production feed and keeps a compact local index of only
 * the records that concern installed software; the full feed is never
 * persisted.
 */
class Feed {

	/**
	 * Option naming the chosen source.
	 */
	public const PROVIDER_OPTION = 'dragoncompliance_feed_provider';

	/**
	 * Source codes.
	 */
	public const PROVIDER_WPVULNERABILITY = 'wpvulnerability';
	public const PROVIDER_WORDFENCE       = 'wordfence';

	/**
	 * Option holding a source change the scanner has not finished applying:
	 * ['from', 'to', 'at' (UTC datetime), 'reason' (settings or upgrade),
	 * 'logged' (whether its evidence row exists)].
	 */
	public const SOURCE_CHANGE_OPTION = 'dragoncompliance_source_change';

	/**
	 * WPVulnerability client, created on first use.
	 *
	 * @var Wpvulnerability|null
	 */
	private ?Wpvulnerability $wpvulnerability = null;

	/**
	 * Feed endpoint. Hard-coded on purpose: this URL must never be
	 * filterable or admin-editable.
	 */
	public const URL = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production';

	/**
	 * The only hosts the Wordfence feed may ever be fetched from.
	 *
	 * The dragoncompliance_feed_source filter can change the request, but this
	 * allowlist decides the host, so a filter can never point the fetch (and
	 * any credentials it carries) at another host. Anything not on this list,
	 * or not HTTPS, falls back to the trusted default.
	 *
	 * @var array<string>
	 */
	private const ALLOWED_HOSTS = array( 'www.wordfence.com' );

	/**
	 * Refuse to keep a downloaded feed file larger than this. It is a sanity
	 * cap on the on-disk temp file (compressed on the wire, but the transport
	 * may store it decompressed at ~150 MB), not a memory bound — stream_index()
	 * keeps memory flat regardless of feed size.
	 */
	public const MAX_BYTES = 512 * 1024 * 1024;

	/**
	 * Per-record cap for the streaming parser. Real records are a few KB; a
	 * feed carrying a record this large is corrupt, and the refresh is abandoned
	 * (keeping the last-good index) rather than buffering it into memory.
	 */
	public const MAX_RECORD_BYTES = 1024 * 1024;

	/**
	 * Resolve where and how the feed is fetched.
	 *
	 * Defaults to the free plugin's own path: the Wordfence endpoint with the
	 * customer's token (or no auth when no token is set). The
	 * dragoncompliance_feed_source filter can adjust the request; the result is
	 * validated by allow_source() so the plugin never fetches an untrusted host.
	 *
	 * @return array{url:string,headers:array<string,string>,configured:bool}
	 */
	private function source(): array {
		$token   = $this->api_token();
		$default = array(
			'url'        => self::URL,
			'headers'    => array(),
			'configured' => '' !== $token,
		);

		/**
		 * Filter the vulnerability-feed source.
		 *
		 * Return an array of {url, headers, configured}. The url must be HTTPS on
		 * www.wordfence.com, or the filtered value is discarded and the default
		 * source is used, so the plugin never accepts an arbitrary URL. The
		 * default carries no credentials: the customer's Wordfence token is
		 * attached after filtering, so it is never handed to filter callbacks.
		 * Applies only while Wordfence Intelligence is the chosen source.
		 *
		 * @since 1.0.6
		 *
		 * @param array $default Default (Wordfence) source descriptor, without credentials.
		 * @param Feed  $feed    The feed instance.
		 */
		$filtered = apply_filters( 'dragoncompliance_feed_source', $default, $this );

		return self::with_token( self::allow_source( $default, $filtered ), $token );
	}

	/**
	 * Attach the customer's Wordfence token to a Wordfence-bound source.
	 *
	 * Runs after allow_source(), so the token only ever travels to
	 * www.wordfence.com and never passes through the filter. A source that
	 * already carries its own Authorization header is left alone.
	 *
	 * @param array  $source Validated source descriptor.
	 * @param string $token  Wordfence API token ('' when none).
	 * @return array{url:string,headers:array<string,string>,configured:bool}
	 */
	public static function with_token( array $source, string $token ): array {
		if ( '' === $token || 'www.wordfence.com' !== wp_parse_url( $source['url'], PHP_URL_HOST ) ) {
			return $source;
		}
		if ( ! is_array( $source['headers'] ?? null ) ) {
			$source['headers'] = array();
		}
		if ( empty( $source['headers']['Authorization'] ) ) {
			$source['headers']['Authorization'] = 'Bearer ' . $token;
		}
		return $source;
	}

	/**
	 * Validate a filtered feed source against the host allowlist.
	 *
	 * Pure and static so the security-critical decision can be tested directly.
	 * Any source whose URL is missing, non-HTTPS, or points anywhere other than
	 * an allowed host reverts to the trusted default.
	 *
	 * @param array $fallback Default (trusted) source descriptor.
	 * @param mixed $filtered Value returned by the filter.
	 * @return array{url:string,headers:array<string,string>,configured:bool}
	 */
	public static function allow_source( array $fallback, $filtered ): array {
		if ( ! is_array( $filtered ) || empty( $filtered['url'] ) || ! is_string( $filtered['url'] ) ) {
			return $fallback;
		}

		$scheme = wp_parse_url( $filtered['url'], PHP_URL_SCHEME );
		$host   = wp_parse_url( $filtered['url'], PHP_URL_HOST );

		if ( 'https' !== $scheme || ! is_string( $host ) || ! in_array( $host, self::ALLOWED_HOSTS, true ) ) {
			return $fallback;
		}

		return $filtered;
	}

	/**
	 * Deterministic slug map (sorted) for the change signature.
	 *
	 * @param array $slug_map Installed software map.
	 * @return array
	 */
	private static function sorted_slug_map( array $slug_map ): array {
		$sorted = array();
		foreach ( array( 'core', 'plugin', 'theme' ) as $type ) {
			$entries = (array) ( $slug_map[ $type ] ?? array() );
			ksort( $entries );
			$sorted[ $type ] = $entries;
		}
		return $sorted;
	}

	/**
	 * Build the compact index from a decoded feed.
	 *
	 * Pure. One index entry per (vulnerability, matching software) pair,
	 * covering only slugs present in the slug map. Tolerant of malformed
	 * records: they are skipped and counted, never fatal.
	 *
	 * @param array $feed     Decoded feed (records keyed by UUID).
	 * @param array $slug_map ['core'=>[slug=>version], 'plugin'=>…, 'theme'=>…].
	 * @return array{records:array,skipped:int,total:int}
	 */
	public static function index_records( array $feed, array $slug_map ): array {
		$records = array();
		$skipped = 0;
		$total   = 0;

		foreach ( $feed as $record ) {
			++$total;
			$matches = is_array( $record ) ? self::index_record( $record, $slug_map ) : null;
			if ( null === $matches ) {
				++$skipped;
				continue;
			}
			foreach ( $matches as $match ) {
				$records[] = $match;
			}
		}

		return array(
			'records' => $records,
			'skipped' => $skipped,
			'total'   => $total,
		);
	}

	/**
	 * Compact index entries for a single feed record.
	 *
	 * @param array $record   One decoded feed record.
	 * @param array $slug_map Installed software map.
	 * @return array|null List of compact records (0+) for installed slugs, or
	 *                    null when the record is malformed (counts as skipped).
	 */
	public static function index_record( array $record, array $slug_map ): ?array {
		if ( empty( $record['id'] ) || ! isset( $record['software'] ) || ! is_array( $record['software'] ) ) {
			return null;
		}

		$cvss     = isset( $record['cvss'] ) && is_array( $record['cvss'] ) ? $record['cvss'] : array();
		$severity = strtolower( (string) ( $cvss['rating'] ?? '' ) );

		$matches = array();
		foreach ( $record['software'] as $software ) {
			if ( ! is_array( $software ) || ! isset( $software['type'], $software['slug'] ) ) {
				continue;
			}
			$type = (string) $software['type'];
			$slug = (string) $software['slug'];
			if ( ! isset( $slug_map[ $type ][ $slug ] ) ) {
				continue;
			}

			$affected = array();
			foreach ( (array) ( $software['affected_versions'] ?? array() ) as $range ) {
				if ( ! is_array( $range ) || ! isset( $range['from_version'], $range['to_version'] ) ) {
					continue;
				}
				$affected[] = array(
					'from'           => (string) $range['from_version'],
					'from_inclusive' => (bool) ( $range['from_inclusive'] ?? true ),
					'to'             => (string) $range['to_version'],
					'to_inclusive'   => (bool) ( $range['to_inclusive'] ?? true ),
				);
			}

			$matches[] = array(
				'vuln_id'          => sanitize_text_field( (string) $record['id'] ),
				'title'            => sanitize_text_field( (string) ( $record['title'] ?? '' ) ),
				'cve'              => sanitize_text_field( (string) ( $record['cve'] ?? '' ) ),
				'severity'         => '' !== $severity ? sanitize_key( $severity ) : 'unknown',
				'cvss'             => (float) ( $cvss['score'] ?? 0 ),
				'type'             => sanitize_key( $type ),
				'slug'             => sanitize_text_field( $slug ),
				'affected'         => $affected,
				'patched'          => (bool) ( $software['patched'] ?? false ),
				'patched_versions' => array_map( 'sanitize_text_field', array_map( 'strval', (array) ( $software['patched_versions'] ?? array() ) ) ),
				'published'        => sanitize_text_field( (string) ( $record['published'] ?? '' ) ),
			);
		}

		return $matches;
	}

	/**
	 * Stream a large feed file, keeping only records for installed slugs.
	 *
	 * The production feed decompresses to ~150 MB / tens of thousands of
	 * records, which `json_decode`ing whole would need ~500 MB of memory and
	 * OOM typical shared hosting. Instead we scan the JSON object one top-level
	 * record at a time (string-aware brace matching), decode each ~4 KB record
	 * on its own, and discard everything that does not match an installed slug.
	 * Peak memory stays in single-digit MB regardless of feed size. A gzip file
	 * is decompressed on the fly via the zlib stream wrapper.
	 *
	 * @param string $path     Path to the downloaded feed (gzip or plain JSON).
	 * @param array  $slug_map Installed software map.
	 * @return array{records:array,skipped:int,total:int,error:string} error is '' or 'record_too_large'.
	 */
	public static function stream_index( string $path, array $slug_map ): array {
		$records = array();
		$skipped = 0;
		$total   = 0;
		$error   = '';

		$head   = (string) file_get_contents( $path, false, null, 0, 2 ); // phpcs:ignore WordPressVIPMinimum.Performance.FetchingRemoteData.FileGetContentsUnknown, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Two-byte gzip magic sniff on a LOCAL temp file; WP_Filesystem cannot do a bounded partial read.
		$source = ( "\x1f\x8b" === $head ) ? 'compress.zlib://' . $path : $path;
		$handle = fopen( $source, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Streaming a local temp file to bound memory; WP_Filesystem has no streaming read.
		if ( false === $handle ) {
			return array(
				'records' => array(),
				'skipped' => 0,
				'total'   => 0,
				'error'   => '',
			);
		}

		$depth     = 0;
		$in_string = false;
		$escape    = false;
		$capturing = false;
		$buffer    = '';

		while ( ! feof( $handle ) ) {
			$chunk = fread( $handle, 65536 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Bounded-memory streaming of the 150MB feed; WP_Filesystem has no chunked read.
			if ( '' === $chunk || false === $chunk ) {
				break;
			}
			$length = strlen( $chunk );
			for ( $i = 0; $i < $length; $i++ ) {
				$char = $chunk[ $i ];
				if ( $capturing ) {
					$buffer .= $char;
					if ( strlen( $buffer ) > self::MAX_RECORD_BYTES ) {
						$error = 'record_too_large';
						break 2;
					}
				}
				if ( $in_string ) {
					if ( $escape ) {
						$escape = false;
					} elseif ( '\\' === $char ) {
						$escape = true;
					} elseif ( '"' === $char ) {
						$in_string = false;
					}
					continue;
				}
				if ( '"' === $char ) {
					$in_string = true;
					continue;
				}
				if ( '{' === $char ) {
					++$depth;
					if ( 2 === $depth && ! $capturing ) {
						$capturing = true;
						$buffer    = '{';
					}
					continue;
				}
				if ( '}' === $char ) {
					--$depth;
					if ( 1 === $depth && $capturing ) {
						$capturing = false;
						++$total;
						$decoded = json_decode( $buffer, true );
						$matches = is_array( $decoded ) ? self::index_record( $decoded, $slug_map ) : null;
						if ( null === $matches ) {
							++$skipped;
						} else {
							foreach ( $matches as $match ) {
								$records[] = $match;
							}
						}
						$buffer = '';
					}
				}
			}
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Closing the streamed temp file handle.

		if ( '' !== $error ) {
			return array(
				'records' => array(),
				'skipped' => 0,
				'total'   => 0,
				'error'   => $error,
			);
		}

		return array(
			'records' => $records,
			'skipped' => $skipped,
			'total'   => $total,
			'error'   => '',
		);
	}

	/**
	 * Fetch the feed and rebuild the local index, recording the outcome.
	 *
	 * A failure never touches the index or the ETag — the last-good data keeps
	 * serving — but it is written into the feed meta so the admin screens can
	 * say why monitoring has no fresh data, and announced on
	 * dragoncompliance_feed_failed.
	 *
	 * With WPVulnerability as the source, each installed component is looked up
	 * instead (see Wpvulnerability::refresh()), which records its own outcome.
	 *
	 * @param array $slug_map Installed software map (see index_records).
	 * @return array|\WP_Error Summary array on success (or unchanged 304).
	 */
	public function refresh( array $slug_map ) {
		if ( ! $this->uses_wordfence() ) {
			return $this->wpvulnerability()->refresh( $slug_map );
		}

		$result = $this->do_refresh( $slug_map );
		$meta   = get_option( 'dragoncompliance_feed_meta', array() );
		$meta   = is_array( $meta ) ? $meta : array();

		if ( is_wp_error( $result ) ) {
			$meta['last_error'] = array(
				'code'    => $result->get_error_code(),
				'message' => $result->get_error_message(),
				'at'      => time(),
			);
			update_option( 'dragoncompliance_feed_meta', $meta, false );

			/**
			 * Fires when a vulnerability-feed refresh fails.
			 *
			 * @since 1.0.6
			 *
			 * @param \WP_Error $result The failure (code, message; HTTP failures carry ['status']).
			 * @param string    $url    The feed URL that was used (no credentials).
			 */
			do_action( 'dragoncompliance_feed_failed', $result, (string) $this->source()['url'] );
		} elseif ( isset( $meta['last_error'] ) ) {
			unset( $meta['last_error'] );
			update_option( 'dragoncompliance_feed_meta', $meta, false );
		}

		return $result;
	}

	/**
	 * The most recent refresh failure, or null when the last refresh succeeded.
	 *
	 * @return array{code:string,message:string,at:int}|null
	 */
	public function last_error(): ?array {
		$meta = $this->uses_wordfence() ? get_option( 'dragoncompliance_feed_meta', array() ) : Wpvulnerability::meta();
		if ( ! is_array( $meta ) || empty( $meta['last_error'] ) || ! is_array( $meta['last_error'] ) ) {
			return null;
		}
		return array(
			'code'    => (string) ( $meta['last_error']['code'] ?? '' ),
			'message' => (string) ( $meta['last_error']['message'] ?? '' ),
			'at'      => (int) ( $meta['last_error']['at'] ?? 0 ),
		);
	}

	/**
	 * Whether a Wordfence token is stored on this site (regardless of source).
	 */
	public function token_set(): bool {
		return '' !== $this->api_token();
	}

	/**
	 * The chosen source.
	 *
	 * A site that has never chosen keeps Wordfence when it already stores a
	 * token, and gets WPVulnerability otherwise. The answer is stored, so a
	 * token entered later does not switch the source by itself.
	 *
	 * @return string PROVIDER_WPVULNERABILITY or PROVIDER_WORDFENCE.
	 */
	public function provider(): string {
		$stored = get_option( self::PROVIDER_OPTION, '' );
		if ( in_array( $stored, array( self::PROVIDER_WPVULNERABILITY, self::PROVIDER_WORDFENCE ), true ) ) {
			return $stored;
		}

		// The raw option, not api_token(): decrypting can delete an unreadable token.
		$token  = get_option( 'dragoncompliance_api_token', '' );
		$chosen = is_string( $token ) && '' !== $token ? self::PROVIDER_WORDFENCE : self::PROVIDER_WPVULNERABILITY;
		if ( add_option( self::PROVIDER_OPTION, $chosen ) && self::PROVIDER_WORDFENCE !== $chosen && self::had_wordfence_data() ) {
			// Earlier versions read only the Wordfence feed; this site's findings came from it.
			self::note_source_change( self::PROVIDER_WORDFENCE, $chosen, 'upgrade' );
		}
		return $chosen;
	}

	/**
	 * Whether this site fetched the Wordfence feed before a source was chosen.
	 */
	private static function had_wordfence_data(): bool {
		$meta  = get_option( 'dragoncompliance_feed_meta', array() );
		$index = get_option( 'dragoncompliance_feed_index', array() );
		return ( is_array( $meta ) && ! empty( $meta['fetched_at'] ) ) || ( is_array( $index ) && array() !== $index );
	}

	/**
	 * Remember a source change for the next scan with data to apply.
	 *
	 * A change made while another is pending keeps the original source and
	 * time, and a change back to that source cancels it.
	 *
	 * @param string $from   Source before the change.
	 * @param string $to     Source after it.
	 * @param string $reason settings or upgrade.
	 */
	public static function note_source_change( string $from, string $to, string $reason = 'settings' ): void {
		$pending = self::pending_source_change();
		if ( null !== $pending ) {
			$from = $pending['from'];
		}
		if ( $from === $to ) {
			delete_option( self::SOURCE_CHANGE_OPTION );
			return;
		}
		update_option(
			self::SOURCE_CHANGE_OPTION,
			array(
				'from'   => $from,
				'to'     => $to,
				'at'     => null !== $pending ? $pending['at'] : gmdate( 'Y-m-d H:i:s' ),
				'reason' => null !== $pending ? $pending['reason'] : $reason,
				'logged' => null !== $pending ? $pending['logged'] : 'upgrade' !== $reason,
			),
			false
		);
	}

	/**
	 * The pending source change, or null.
	 *
	 * @return array{from:string,to:string,at:string,reason:string,logged:bool}|null
	 */
	public static function pending_source_change(): ?array {
		$stored = get_option( self::SOURCE_CHANGE_OPTION, array() );
		if ( ! is_array( $stored ) || ! is_string( $stored['from'] ?? null ) || ! is_string( $stored['to'] ?? null ) || ! is_string( $stored['at'] ?? null ) ) {
			return null;
		}
		return array(
			'from'   => $stored['from'],
			'to'     => $stored['to'],
			'at'     => $stored['at'],
			'reason' => 'upgrade' === ( $stored['reason'] ?? '' ) ? 'upgrade' : 'settings',
			'logged' => ! empty( $stored['logged'] ),
		);
	}

	/**
	 * Mark the pending change's evidence row as written.
	 */
	public static function source_change_logged(): void {
		$stored = get_option( self::SOURCE_CHANGE_OPTION, array() );
		if ( is_array( $stored ) && array() !== $stored ) {
			$stored['logged'] = true;
			update_option( self::SOURCE_CHANGE_OPTION, $stored, false );
		}
	}

	/**
	 * Forget the pending source change once it is applied.
	 */
	public static function clear_source_change(): void {
		delete_option( self::SOURCE_CHANGE_OPTION );
	}

	/**
	 * Whether the Wordfence feed is the source in use.
	 */
	public function uses_wordfence(): bool {
		return self::PROVIDER_WORDFENCE === $this->provider();
	}

	/**
	 * Whether monitoring can fetch data: always with WPVulnerability, and with
	 * Wordfence once a token (or a filtered source) is configured.
	 */
	public function monitoring_ready(): bool {
		return ! $this->uses_wordfence() || $this->has_token();
	}

	/**
	 * The WPVulnerability client.
	 */
	protected function wpvulnerability(): Wpvulnerability {
		if ( null === $this->wpvulnerability ) {
			$this->wpvulnerability = new Wpvulnerability();
		}
		return $this->wpvulnerability;
	}

	/**
	 * Use a given WPVulnerability client (tests).
	 *
	 * @param Wpvulnerability $client Client.
	 */
	public function set_wpvulnerability( Wpvulnerability $client ): void {
		$this->wpvulnerability = $client;
	}

	/**
	 * Components the last refresh could not check, "type|slug" => reason.
	 * Always empty for the Wordfence feed, which covers everything or nothing.
	 *
	 * @return array<string,string>
	 */
	public function unchecked(): array {
		return $this->uses_wordfence() ? array() : Wpvulnerability::unchecked();
	}

	/**
	 * Whether the scan has vulnerability data to compare against, so that a
	 * finding missing from the matches may be resolved.
	 *
	 * The Wordfence index is only trusted when non-empty. A WPVulnerability
	 * index can be empty on a site with no known vulnerabilities, so it counts
	 * once at least one lookup has ever succeeded.
	 */
	public function has_data(): bool {
		if ( array() !== $this->index() ) {
			return true;
		}
		return ! $this->uses_wordfence() && ! empty( Wpvulnerability::meta()['fetched_at'] );
	}

	/**
	 * Fetch the feed and rebuild the local index.
	 *
	 * @param array $slug_map Installed software map (see index_records).
	 * @return array|\WP_Error Summary array on success (or unchanged 304).
	 */
	private function do_refresh( array $slug_map ) {
		$source = $this->source();
		if ( empty( $source['configured'] ) ) {
			return new \WP_Error( 'dragoncompliance_no_token', __( 'No Wordfence Intelligence API token is configured.', 'dragon-compliance' ) );
		}

		$meta         = get_option( 'dragoncompliance_feed_meta', array() );
		$slug_map_sig = md5( (string) wp_json_encode( self::sorted_slug_map( $slug_map ) ) );
		$headers      = array_merge(
			array( 'Accept' => 'application/json' ),
			(array) $source['headers']
		);
		// Only send a conditional request when the installed software is the
		// same as at the last fetch. If a plugin/theme was added or updated, a
		// 304 would leave the index without an entry for it — a silent false
		// negative — so we force a full refresh instead.
		// Likewise never revalidate an empty local index: a 304 would keep it empty.
		if ( ! empty( $meta['etag'] ) && ( $meta['slug_map_sig'] ?? '' ) === $slug_map_sig && array() !== $this->index() ) {
			$headers['If-None-Match'] = (string) $meta['etag'];
		}

		// Stream the response straight to a temp file rather than into memory:
		// the production feed decompresses to ~150 MB, and holding + decoding it
		// whole would OOM typical shared hosting. stream_index() then walks that
		// file one record at a time in a few MB of memory.
		if ( ! function_exists( 'wp_tempnam' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$tmp = wp_tempnam( 'dragoncompliance-feed' );
		if ( ! $tmp ) {
			return new \WP_Error( 'dragoncompliance_feed_tmp', __( 'Could not create a temporary file for the vulnerability feed.', 'dragon-compliance' ) );
		}

		$response = wp_safe_remote_get(
			(string) $source['url'],
			array(
				'timeout'     => 120,
				// Core's default user agent carries the site address.
				'user-agent'  => 'DragonCompliance/' . DRAGONCOMPLIANCE_VERSION,
				'headers'     => $headers,
				'stream'      => true,
				'filename'    => $tmp,
				// Neither endpoint redirects; following one would carry the
				// auth headers to wherever it pointed.
				'redirection' => 0,
			)
		);
		if ( is_wp_error( $response ) ) {
			wp_delete_file( $tmp );
			return $response;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 304 === $code ) {
			wp_delete_file( $tmp );
			$meta['fetched_at']   = time();
			$meta['slug_map_sig'] = $slug_map_sig;
			update_option( 'dragoncompliance_feed_meta', $meta, false );
			return array( 'unchanged' => true );
		}
		if ( 200 !== $code ) {
			wp_delete_file( $tmp );
			return new \WP_Error(
				'dragoncompliance_feed_http',
				sprintf(
					/* translators: %d: HTTP status code. */
					__( 'Vulnerability feed request failed with HTTP %d.', 'dragon-compliance' ),
					$code
				),
				array( 'status' => $code )
			);
		}

		// Sanity cap on the downloaded file (compressed on the wire, so ~tens of
		// MB); the streaming parser bounds memory regardless of feed size.
		if ( (int) filesize( $tmp ) > self::MAX_BYTES ) {
			wp_delete_file( $tmp );
			return new \WP_Error( 'dragoncompliance_feed_too_large', __( 'Vulnerability feed response exceeded the size limit.', 'dragon-compliance' ) );
		}

		$index = self::stream_index( $tmp, $slug_map );
		wp_delete_file( $tmp );

		if ( '' !== ( $index['error'] ?? '' ) || 0 === $index['total'] ) {
			return new \WP_Error( 'dragoncompliance_feed_invalid', __( 'Vulnerability feed response could not be parsed.', 'dragon-compliance' ) );
		}

		update_option( 'dragoncompliance_feed_index', $index['records'], false );
		update_option(
			'dragoncompliance_feed_meta',
			array(
				'etag'         => (string) wp_remote_retrieve_header( $response, 'etag' ),
				'fetched_at'   => time(),
				'slug_map_sig' => $slug_map_sig,
				'skipped'      => $index['skipped'],
				'total'        => $index['total'],
			),
			false
		);

		return array(
			'records' => count( $index['records'] ),
			'skipped' => $index['skipped'],
			'total'   => $index['total'],
		);
	}

	/**
	 * The cached compact index.
	 *
	 * @return array
	 */
	public function index(): array {
		if ( ! $this->uses_wordfence() ) {
			return Wpvulnerability::index();
		}
		$index = get_option( 'dragoncompliance_feed_index', array() );
		return is_array( $index ) ? $index : array();
	}

	/**
	 * Seconds since the last successful fetch, or null if never fetched.
	 */
	public function age(): ?int {
		$meta = $this->uses_wordfence() ? get_option( 'dragoncompliance_feed_meta', array() ) : Wpvulnerability::meta();
		if ( empty( $meta['fetched_at'] ) ) {
			return null;
		}
		return max( 0, time() - (int) $meta['fetched_at'] );
	}

	/**
	 * Whether the Wordfence feed has a usable source configured: a token is
	 * set, or a filtered source says it is configured.
	 */
	public function has_token(): bool {
		return ! empty( $this->source()['configured'] );
	}

	/**
	 * Decrypted API token, empty string when unset or undecryptable.
	 */
	private function api_token(): string {
		$stored = get_option( 'dragoncompliance_api_token', '' );
		if ( ! is_string( $stored ) || '' === $stored ) {
			return '';
		}
		$token = Crypto::decrypt( $stored );
		if ( null === $token ) {
			// Fail safe: undecryptable ciphertext is useless — clear it so
			// the UI prompts for the token again instead of re-encrypting garbage.
			delete_option( 'dragoncompliance_api_token' );
			return '';
		}
		return $token;
	}
}
