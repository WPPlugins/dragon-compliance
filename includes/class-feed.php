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
	 * Refuse to keep a downloaded feed file larger than this. It is a sanity
	 * cap on the on-disk temp file (compressed on the wire, but the transport
	 * may store it decompressed at ~150 MB), not a memory bound — stream_index()
	 * keeps memory flat regardless of feed size.
	 */
	public const MAX_BYTES = 512 * 1024 * 1024;

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
	 * @return array{records:array,skipped:int,total:int}
	 */
	public static function stream_index( string $path, array $slug_map ): array {
		$records = array();
		$skipped = 0;
		$total   = 0;

		$head   = (string) file_get_contents( $path, false, null, 0, 2 ); // phpcs:ignore WordPressVIPMinimum.Performance.FetchingRemoteData.FileGetContentsUnknown, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Two-byte gzip magic sniff on a LOCAL temp file; WP_Filesystem cannot do a bounded partial read.
		$source = ( "\x1f\x8b" === $head ) ? 'compress.zlib://' . $path : $path;
		$handle = fopen( $source, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Streaming a local temp file to bound memory; WP_Filesystem has no streaming read.
		if ( false === $handle ) {
			return array(
				'records' => array(),
				'skipped' => 0,
				'total'   => 0,
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

		return array(
			'records' => $records,
			'skipped' => $skipped,
			'total'   => $total,
		);
	}

	/**
	 * Fetch the feed and rebuild the local index.
	 *
	 * @param array $slug_map Installed software map (see index_records).
	 * @return array|\WP_Error Summary array on success (or unchanged 304).
	 */
	public function refresh( array $slug_map ) {
		$token = $this->api_token();
		if ( '' === $token ) {
			return new \WP_Error( 'dragoncompliance_no_token', __( 'No Wordfence Intelligence API token is configured.', 'dragon-compliance' ) );
		}

		$meta         = get_option( 'dragoncompliance_feed_meta', array() );
		$slug_map_sig = md5( (string) wp_json_encode( self::sorted_slug_map( $slug_map ) ) );
		$headers      = array(
			'Authorization' => 'Bearer ' . $token,
			'Accept'        => 'application/json',
		);
		// Only send a conditional request when the installed software is the
		// same as at the last fetch. If a plugin/theme was added or updated, a
		// 304 would leave the index without an entry for it — a silent false
		// negative — so we force a full refresh instead.
		if ( ! empty( $meta['etag'] ) && ( $meta['slug_map_sig'] ?? '' ) === $slug_map_sig ) {
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
			self::URL,
			array(
				'timeout'  => 120,
				'headers'  => $headers,
				'stream'   => true,
				'filename' => $tmp,
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
				)
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

		if ( 0 === $index['total'] ) {
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
	 * Whether an API token is configured.
	 */
	public function has_token(): bool {
		return '' !== $this->api_token();
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
