<?php
/**
 * Wordfence Intelligence vulnerability feed: fetch, index, cache.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Fetches the production vulnerability feed and keeps a compact local index
 * of only the records that concern installed software. The full feed is
 * never persisted.
 */
class Feed {

	/**
	 * Feed endpoint. Hard-coded on purpose: this URL must never be
	 * filterable or admin-editable.
	 */
	public const URL = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production';

	/**
	 * The only hosts the feed may ever be fetched from.
	 *
	 * Pro can redirect the fetch to the Dragon Core proxy through the
	 * dragoncompliance_feed_source filter, but the free plugin decides the
	 * allowlist, so a filter — even a malicious one — can never point the fetch
	 * (and the licence key it carries) at an attacker-chosen host. Anything not
	 * on this list, or not HTTPS, falls back to the trusted default.
	 *
	 * @var array<string>
	 */
	private const ALLOWED_HOSTS = array( 'www.wordfence.com', 'api.dragoncore.ltd' );

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
	 * dragoncompliance_feed_source filter lets Pro swap in the Dragon Core proxy;
	 * the result is validated by allow_source() so the free plugin never fetches
	 * an untrusted host.
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
		 * Return an array of {url, headers, configured}. The url's host must be
		 * one of the free plugin's two known hosts over HTTPS, or the filtered
		 * value is discarded and the default Wordfence source is used. This is
		 * how Dragon Compliance Pro points monitoring at the Dragon Core proxy
		 * without the free plugin ever accepting an arbitrary URL. The default
		 * carries no credentials: the customer's Wordfence token is attached
		 * after filtering, only to a Wordfence-bound source, so it is never
		 * handed to filter callbacks.
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
	 * dragoncompliance_feed_failed so an alternative source (Pro) can react.
	 *
	 * @param array $slug_map Installed software map (see index_records).
	 * @return array|\WP_Error Summary array on success (or unchanged 304).
	 */
	public function refresh( array $slug_map ) {
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
		$meta = get_option( 'dragoncompliance_feed_meta', array() );
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
	 * Whether the feed is currently sourced from somewhere other than Wordfence
	 * (i.e. Pro has pointed it at the Dragon Core proxy).
	 */
	public function is_proxied(): bool {
		return 'www.wordfence.com' !== wp_parse_url( (string) $this->source()['url'], PHP_URL_HOST );
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
		$tmp = wp_tempnam( 'dragoncompliance-feed' );
		if ( ! $tmp ) {
			return new \WP_Error( 'dragoncompliance_feed_tmp', __( 'Could not create a temporary file for the vulnerability feed.', 'dragon-compliance' ) );
		}

		$response = wp_safe_remote_get(
			(string) $source['url'],
			array(
				'timeout'     => 120,
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
		$index = get_option( 'dragoncompliance_feed_index', array() );
		return is_array( $index ) ? $index : array();
	}

	/**
	 * Seconds since the last successful fetch, or null if never fetched.
	 */
	public function age(): ?int {
		$meta = get_option( 'dragoncompliance_feed_meta', array() );
		if ( empty( $meta['fetched_at'] ) ) {
			return null;
		}
		return max( 0, time() - (int) $meta['fetched_at'] );
	}

	/**
	 * Whether the feed has a usable source configured.
	 *
	 * True when a Wordfence token is set, or when Pro has pointed the feed at
	 * the Dragon Core proxy. The admin uses this to decide whether to prompt for
	 * a token, so a licensed Pro site correctly shows monitoring as active
	 * without one.
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
