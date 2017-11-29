import pytest
from ethereum.utils import privtoaddr
from ethereum.tools import tester
from ethereum.tests.utils import new_db
from ethereum.db import EphemDB
from ethereum.hybrid_casper import casper_utils
from ethereum.slogging import get_logger
from ethereum.tests.hybrid_casper.testing_lang import TestLangHybrid
log = get_logger('test.chain')
logger = get_logger()

_db = new_db()

# from ethereum.slogging import configure_logging
# config_string = ':info,eth.chain:debug,test.chain:info'
# configure_logging(config_string=config_string)

EPOCH_LENGTH = 25
SLASH_DELAY = 864
ALLOC = {a: {'balance': 500*10**19} for a in tester.accounts[:10]}
k0, k1, k2, k3, k4, k5, k6, k7, k8, k9 = tester.keys[:10]
a0, a1, a2, a3, a4, a5, a6, a7, a8, a9 = tester.accounts[:10]


@pytest.fixture(scope='function')
def db():
    return EphemDB()
alt_db = db

def init_chain_and_casper():
    genesis = casper_utils.make_casper_genesis(ALLOC, EPOCH_LENGTH, 100, 0.02, 0.002)
    t = tester.Chain(genesis=genesis)
    casper = tester.ABIContract(t, casper_utils.casper_abi, t.chain.config['CASPER_ADDRESS'])
    return t, casper


# Mines blocks required for number_of_epochs epoch changes, plus an offset of 2 blocks
def mine_epochs(t, number_of_epochs):
    distance_to_next_epoch = (EPOCH_LENGTH - t.head_state.block_number) % EPOCH_LENGTH
    number_of_blocks = distance_to_next_epoch + EPOCH_LENGTH*(number_of_epochs-1) + 2
    return t.mine(number_of_blocks=number_of_blocks)


def test_mining(db):
    t, casper = init_chain_and_casper()
    assert t.chain.state.block_number == 0
    assert t.chain.state.block_difficulty == 1
    for i in range(2):
        t.mine()
        assert t.chain.state.block_number == i + 1


def test_mining_block_rewards(db):
    t, casper = init_chain_and_casper()
    genesis = t.mine(coinbase=a1)
    blk2 = t.mine(coinbase=a1)
    blk3 = t.mine(coinbase=a1)
    blk4 = t.mine(coinbase=a1)
    t.mine(coinbase=a1)
    assert t.chain.state.get_balance(a1) == t.chain.env.config['BLOCK_REWARD'] + t.chain.mk_poststate_of_blockhash(blk4.hash).get_balance(a1)
    assert t.chain.state.get_balance(a1) == t.chain.env.config['BLOCK_REWARD'] * 2 + t.chain.mk_poststate_of_blockhash(blk3.hash).get_balance(a1)
    assert t.chain.state.get_balance(a1) == t.chain.env.config['BLOCK_REWARD'] * 3 + t.chain.mk_poststate_of_blockhash(blk2.hash).get_balance(a1)
    assert t.chain.state.get_balance(a1) == t.chain.env.config['BLOCK_REWARD'] * 4 + t.chain.mk_poststate_of_blockhash(genesis.hash).get_balance(a1)
    assert blk2.prevhash == genesis.hash


def test_simple_chain(db):
    t, casper = init_chain_and_casper()
    t.tx(k0, a1, 20, gasprice=0)
    blk2 = t.mine()
    blk3 = t.mine()
    assert blk2.hash in t.chain
    assert blk3.hash in t.chain
    assert t.chain.has_block(blk2.hash)
    assert t.chain.has_block(blk3.hash)
    assert t.chain.get_block(blk2.hash) == blk2
    assert t.chain.get_block(blk3.hash) == blk3
    assert t.chain.head == blk3
    assert t.chain.get_children(blk2) == [blk3]
    assert t.chain.get_chain() == [blk2, blk3]
    assert t.chain.get_block_by_number(1) == blk2
    assert t.chain.get_block_by_number(2) == blk3
    assert not t.chain.get_block_by_number(3)


def test_head_change_for_longer_pow_chain(db):
    """" [L & R are blocks]
    Local: L0, L1
    add
    Remote: R0, R1, R2
    """
    t, casper = init_chain_and_casper()
    t.mine()
    root_hash = t.chain.head_hash
    L = t.mine(2)
    assert t.chain.head_hash == L.hash
    t.change_head(root_hash)
    R = t.mine(2)
    # Test that we just need one more block before the head switches
    assert t.chain.head_hash == L.hash
    R = t.mine(1)
    assert t.chain.head_hash == R.hash


def test_no_gas_cost_for_successful_casper_vote(db):
    """ This tests that the chain is the chain is """
    sender = b'\x82\xa9x\xb3\xf5\x96*[\tW\xd9\xee\x9e\xefG.\xe5[B\xf1'
    test_string = 'B J0 B B'
    test = TestLangHybrid(15, 100, 0.02, 0.002)
    test.parse(test_string)
    pre_balance = test.t.head_state.get_balance(sender)
    pre_block_gas_used = test.t.head_state.gas_used
    test_string = 'V0'
    test.parse(test_string)
    post_balance = test.t.head_state.get_balance(sender)
    post_block_gas_used = test.t.head_state.gas_used
    assert pre_balance == post_balance
    assert pre_block_gas_used == post_block_gas_used


def test_costs_gas_for_failed_casper_vote(db):
    """ This tests that the chain is the chain is """
    test = TestLangHybrid(15, 100, 0.02, 0.002)
    sender = b'\x82\xa9x\xb3\xf5\x96*[\tW\xd9\xee\x9e\xefG.\xe5[B\xf1'
    pre_join_balance = test.t.head_state.get_balance(sender)
    test_string = 'B J0 B B'
    test.parse(test_string)
    post_join_balance = test.t.head_state.get_balance(sender)
    cost_of_joining = pre_join_balance - post_join_balance
    pre_balance = test.t.head_state.get_balance(sender)
    test_string = 'J1 V0 B B'
    with pytest.raises(AssertionError):
        test.parse(test_string)
    post_balance = test.t.head_state.get_balance(sender)
    # Gas is charged for failed vote
    assert pre_balance > post_balance + cost_of_joining


def test_fails_if_all_casper_vote_transactions_are_not_first(db):
    """ This tests that the chain is the chain is """
    test_string = 'B J0 B B J1 V0 B B'
    test = TestLangHybrid(15, 100, 0.02, 0.002)
    with pytest.raises(AssertionError):
        test.parse(test_string)


def test_no_change_for_more_work_on_non_finalized_descendant(db):
    """ This tests that the chain is the chain is """
    test_string = 'B J0 J1 J2 J3 B B V0 V1 V2 V3 B V0 V1 V2 V3 B S0 B V0 B1 S1 H1 R0 B B B B B H1'
    test = TestLangHybrid(15, 100, 0.02, 0.002)
    test.parse(test_string)


def test_change_head_for_more_votes(db):
    """ This tests that the chain is the chain is """
    test_string = 'B J0 J1 J2 J3 B B V0 V1 V2 V3 B S0 B V0 V1 B1 S1 R0 B B B2 V0 B1 S2 H1 V1 V2 B2 S3 H3'
    test = TestLangHybrid(15, 100, 0.02, 0.002)
    test.parse(test_string)


def test_double_vote_slash(db):
    """ This tests that the chain is the chain is """
    test_string = 'B J0 J1 J2 J3 B B S0 B V0 V1 V2 V3 B1 R0 B V0 B1 X0 B V1 V2 V3 B'
    test = TestLangHybrid(15, 100, 0.02, 0.002)
    test.parse(test_string)


def test_vote_surround_slash(db):
    """ This tests that the chain is the chain is """
    test_string = 'B J0 J1 J2 J3 B B S0 V0 V1 V2 V3 B V0 V1 V2 V3 B V0 V1 V2 V3 R0 B B B B B B B V0 B1'
    test = TestLangHybrid(15, 100, 0.02, 0.002)
    test.parse(test_string)
