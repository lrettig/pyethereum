import copy
from ethereum import utils, config
from ethereum.tools.tester import a0

casper_config = dict(
    # The Casper-specific config declaration
    METROPOLIS_FORK_BLKNUM=0,
    ANTI_DOS_FORK_BLKNUM=0,
    CLEARING_FORK_BLKNUM=0,
    CONSENSUS_STRATEGY='hybrid_casper',
    NULL_SENDER=utils.sha3('NULL_SENDER'),
    EPOCH_LENGTH=50,
    OWNER=a0
)

config.casper_config = {**config.default_config, **casper_config}
