( function ( $ ) {
	'use strict';

	$( function () {
		$( '#dragoncompliance-scan-now' ).on( 'click', function () {
			var $button = $( this );
			var $result = $( '#dragoncompliance-scan-result' );

			$button.prop( 'disabled', true );
			$result.text( dragoncomplianceAdmin.scanning );

			$.post( dragoncomplianceAdmin.ajaxUrl, {
				action: 'dragoncompliance_scan_now',
				nonce: dragoncomplianceAdmin.nonce
			} )
				.done( function ( response ) {
					if ( response && response.success ) {
						window.location.reload();
					} else {
						$result.text( dragoncomplianceAdmin.scanFail );
						$button.prop( 'disabled', false );
					}
				} )
				.fail( function () {
					$result.text( dragoncomplianceAdmin.scanFail );
					$button.prop( 'disabled', false );
				} );
		} );
	} );
}( jQuery ) );
