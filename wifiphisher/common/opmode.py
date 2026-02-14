"""
All logic regarding the Operation Modes (opmodes).
Patched for NetHunter: adds OP_MODE_NETHUNTER.
"""
import sys
import os
import logging
import argparse
import wifiphisher.common.constants as constants

logger = logging.getLogger(__name__)

# Conditional imports - pyric may not be available on Android
try:
    import pyric
    import wifiphisher.common.interfaces as interfaces
    HAS_PYRIC = True
except ImportError:
    HAS_PYRIC = False

try:
    import wifiphisher.extensions.handshakeverify as handshakeverify
    HAS_HANDSHAKE = True
except ImportError:
    HAS_HANDSHAKE = False


class OpMode(object):
    """Manager of the operation mode"""

    def __init__(self):
        self.op_mode = 0x0
        self._is_one_phy_interface = False
        self._perfect_card = None

    def initialize(self, args):
        # In NetHunter mode, skip pyric interface detection
        if getattr(args, 'nethunter', False):
            logger.info("NetHunter mode: skipping pyric interface detection")
            return

        if HAS_PYRIC:
            self._perfect_card, self._is_one_phy_interface = \
                interfaces.is_add_vif_required(args)
        self._check_args(args)

    def _check_args(self, args):
        if getattr(args, 'nethunter', False):
            # In NetHunter mode, most checks don't apply
            return

        if args.presharedkey and \
            (len(args.presharedkey) < 8 or
             len(args.presharedkey) > 64):
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] Pre-shared key must be between 8 and 63 printable'
                     'characters.')

        if args.handshake_capture and not os.path.isfile(
                args.handshake_capture):
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] Handshake capture does not exist.')
        elif args.handshake_capture and HAS_HANDSHAKE and \
                not handshakeverify.is_valid_handshake_capture(
                    args.handshake_capture):
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] Handshake capture does not contain valid handshake')

        if ((args.extensionsinterface and not args.apinterface) or
                (not args.extensionsinterface and args.apinterface)) and \
                not (args.noextensions and args.apinterface):
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] --apinterface (-aI) and --extensionsinterface (-eI)'
                     '(or --noextensions (-nE)) are used in conjuction.')

        if args.noextensions and args.extensionsinterface:
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] --noextensions (-nE) and --extensionsinterface (-eI)'
                     'cannot work together.')

        if args.lure10_exploit and args.noextensions:
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] --lure10-exploit (-lE) and --noextensions (-eJ)'
                     'cannot work together.')

        if args.lure10_exploit and not os.path.isfile(constants.LOCS_DIR +
                                                      args.lure10_exploit):
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] Lure10 capture does not exist. Listing directory'
                     'of captures: ' + str(os.listdir(constants.LOCS_DIR)))

        if (args.mac_ap_interface and args.no_mac_randomization) or \
                (args.mac_extensions_interface and args.no_mac_randomization):
            sys.exit(
                '[' + constants.R + '-' + constants.W +
                '] --no-mac-randomization (-iNM) cannot work together with'
                '--mac-ap-interface or --mac-extensions-interface (-iDM)')

        if args.deauth_essid and args.noextensions:
            sys.exit(
                '[' + constants.R + '-' + constants.W +
                '] --deauth-essid (-dE) cannot work together with'
                '--noextension (-nE)')

        if args.deauth_essid and self._is_one_phy_interface:
            print('[' + constants.R + '!' + constants.W +
                  '] Only one card was found. Wifiphisher will deauth only '
                  'on the target AP channel')

        if args.wpspbc_assoc_interface and not args.wps_pbc:
            sys.exit(
                '[' + constants.R + '!' + constants.W +
                '] --wpspbc-assoc-interface (-wAI) requires --wps-pbc (-wP) option.'
            )

    def set_opmode(self, args, network_manager):
        # NetHunter mode
        if getattr(args, 'nethunter', False):
            self.op_mode = constants.OP_MODE_NETHUNTER
            logger.info("Starting OP_MODE_NETHUNTER (0x10)")
            return

        if not args.internetinterface and not args.noextensions:
            if not self._is_one_phy_interface:
                if args.wpspbc_assoc_interface:
                    self.op_mode = constants.OP_MODE7
                    logger.info("Starting OP_MODE7 (0x7)")
                else:
                    self.op_mode = constants.OP_MODE1
                    logger.info("Starting OP_MODE1 (0x1)")
            else:
                if self._perfect_card is not None:
                    network_manager.add_virtual_interface(self._perfect_card)
                if args.wpspbc_assoc_interface:
                    self.op_mode = constants.OP_MODE8
                    logger.info("Starting OP_MODE8 (0x8)")
                else:
                    self.op_mode = constants.OP_MODE5
                    logger.info("Starting OP_MODE5 (0x5)")
        if args.internetinterface and not args.noextensions:
            if not self._is_one_phy_interface:
                self.op_mode = constants.OP_MODE2
                logger.info("Starting OP_MODE2 (0x2)")
            else:
                if self._perfect_card is not None:
                    network_manager.add_virtual_interface(self._perfect_card)
                self.op_mode = constants.OP_MODE6
                logger.info("Starting OP_MODE6 (0x6)")

        if args.internetinterface and args.noextensions:
            self.op_mode = constants.OP_MODE3
            logger.info("Starting OP_MODE3 (0x3)")
        if args.noextensions and not args.internetinterface:
            self.op_mode = constants.OP_MODE4
            logger.info("Starting OP_MODE4 (0x4)")

    def is_nethunter_mode(self):
        return self.op_mode == constants.OP_MODE_NETHUNTER

    def internet_sharing_enabled(self):
        return self.op_mode in [constants.OP_MODE2, constants.OP_MODE3]

    def extensions_enabled(self):
        if self.op_mode == constants.OP_MODE_NETHUNTER:
            return False
        return self.op_mode in [
            constants.OP_MODE1, constants.OP_MODE2, constants.OP_MODE5,
            constants.OP_MODE6, constants.OP_MODE7, constants.OP_MODE8
        ]

    def freq_hopping_enabled(self):
        if self.op_mode == constants.OP_MODE_NETHUNTER:
            return False
        return self.op_mode in [
            constants.OP_MODE1, constants.OP_MODE2, constants.OP_MODE7
        ]

    def assoc_enabled(self):
        return self.op_mode in [constants.OP_MODE7, constants.OP_MODE8]


def validate_ap_interface(interface):
    """Validate the given interface"""
    if not HAS_PYRIC:
        # On Android/NetHunter, skip pyric validation
        return interface

    if not(pyric.pyw.iswireless(interface) and \
        pyric.pyw.isinterface(interface) and \
        interfaces.does_have_mode(interface, "AP")):

        raise argparse.ArgumentTypeError("Provided interface ({})"
                                         " either does not exist or"
                                         " does not support AP mode" \
                                        .format(interface))
    return interface
