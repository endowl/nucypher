"""
This file is part of nucypher.

nucypher is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

nucypher is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with nucypher.  If not, see <https://www.gnu.org/licenses/>.
"""
from unittest.mock import patch

import pytest
import time
from hendrix.experience import crosstown_traffic
from hendrix.utils.test_utils import crosstownTaskListDecoratorFactory
from umbral.config import default_params
from umbral.signing import Signature

from nucypher.characters.lawful import Ursula
from nucypher.characters.unlawful import Vladimir
from nucypher.config.characters import AliceConfiguration
from nucypher.crypto.api import keccak_digest
from nucypher.crypto.powers import SigningPower
from nucypher.network.nicknames import nickname_from_seed
from nucypher.network.nodes import FleetStateTracker
from nucypher.utilities.logging import GlobalLoggerSettings
from nucypher.utilities.sandbox.constants import INSECURE_DEVELOPMENT_PASSWORD
from nucypher.utilities.sandbox.middleware import MockRestMiddleware, MockRestMiddlewareForLargeFleetTests
from nucypher.utilities.sandbox.ursula import make_federated_ursulas


def test_alice_can_learn_about_a_whole_bunch_of_ursulas(ursula_federated_test_config):
    # First, we need to do some optimizing of this test in order
    # to be able to create a whole bunch of Ursulas without it freezing.
    # BEGIN CRAZY MONKEY PATCHING BLOCK
    class NotAPublicKey:
        _serial = 10000

        @classmethod
        def tick(cls):
            cls._serial += 1

        def __init__(self, serial=None):
            if serial is None:
                self.tick()
                self.serial = str(self._serial).encode()
            else:
                self.serial = serial

        def __bytes__(self):
            return b"not a compressed public key:" + self.serial

        @classmethod
        def from_bytes(cls, some_bytes):
            return cls(serial=some_bytes[-5:])

        def to_bytes(self, *args, **kwargs):
            return b"this is not a public key... but it is 64 bytes.. so, ya know" + self.serial

    class NotAPrivateKey:
        params = default_params()

        fake_signature = Signature.from_bytes(
            b'@\xbfS&\x97\xb3\x9e\x9e\xd3\\j\x9f\x0e\x8fY\x0c\xbeS\x08d\x0b%s\xf6\x17\xe2\xb6\xcd\x95u\xaapON\xd9E\xb3\x10M\xe1\xf4u\x0bL\x99q\xd6\r\x8e_\xe5I\x1e\xe5\xa2\xcf\xe5\x8be_\x077Gz'
        )

        def public_key(self):
            return NotAPublicKey()

        def get_pubkey(self, *args, **kwargs):
            return self.public_key()

        def to_cryptography_privkey(self, *args, **kwargs):
            return self

        def sign(self, *args, **kwargs):
            return b'0D\x02 @\xbfS&\x97\xb3\x9e\x9e\xd3\\j\x9f\x0e\x8fY\x0c\xbeS\x08d\x0b%s\xf6\x17\xe2\xb6\xcd\x95u\xaap\x02 ON\xd9E\xb3\x10M\xe1\xf4u\x0bL\x99q\xd6\r\x8e_\xe5I\x1e\xe5\xa2\xcf\xe5\x8be_\x077Gz'

        @classmethod
        def stamp(cls, *args, **kwargs):
            return cls.fake_signature

        @classmethod
        def signature_bytes(cls, *args, **kwargs):
            return b'@\xbfS&\x97\xb3\x9e\x9e\xd3\\j\x9f\x0e\x8fY\x0c\xbeS\x08d\x0b%s\xf6\x17\xe2\xb6\xcd\x95u\xaapON\xd9E\xb3\x10M\xe1\xf4u\x0bL\x99q\xd6\r\x8e_\xe5I\x1e\xe5\xa2\xcf\xe5\x8be_\x077Gz'

    class NotACert:
        class Subject:
            def get_attributes_for_oid(self, *args, **kwargs):
                class Pseudonym:
                    value = "0x51347fF6eb8F1D39B83B5e9c244Dc2E1E9EB14B4"

                return Pseudonym(), "Or whatever?"

        subject = Subject()

        def public_bytes(self, does_not_matter):
            return b"this is not a cert."

        def public_key(self):
            return NotAPublicKey()

    def do_not_create_cert(*args, **kwargs):
        return NotACert(), NotAPrivateKey()

    def simple_remember(ursula, node, *args, **kwargs):
        address = node.checksum_address
        ursula.known_nodes[address] = node

    class NotARestApp:
        testing = True

    with GlobalLoggerSettings.pause_all_logging_while():
        with patch("nucypher.config.storages.ForgetfulNodeStorage.store_node_certificate",
                   new=lambda *args, **kwargs: "do not store cert."):
            with patch("nucypher.characters.lawful.make_rest_app",
                       new=lambda *args, **kwargs: (NotARestApp(), "this is not a datastore")):
                with patch("nucypher.characters.lawful.load_pem_x509_certificate",
                           new=lambda *args, **kwargs: NotACert()):
                    with patch("nucypher.keystore.keypairs.generate_self_signed_certificate", new=do_not_create_cert):
                        with patch("nucypher.keystore.keypairs.Keypair._private_key_source",
                                   new=lambda *args, **kwargs: NotAPrivateKey()):
                            with patch("nucypher.characters.lawful.Ursula.remember_node", new=simple_remember):
                                _ursulas = make_federated_ursulas(ursula_config=ursula_federated_test_config,
                                                                  quantity=5000, know_each_other=False)
                                # END FIRST CRAZY MONKEY PATCHING BLOCK
                                all_ursulas = {u.checksum_address: u for u in _ursulas}
                                for ursula in _ursulas:
                                    ursula.known_nodes._nodes = all_ursulas
                                    ursula.known_nodes.checksum = b"This is a fleet state checksum..".hex()
    config = AliceConfiguration(dev_mode=True,
                                network_middleware=MockRestMiddlewareForLargeFleetTests(),
                                known_nodes=_ursulas,
                                federated_only=True,
                                abort_on_learning_error=True,
                                save_metadata=False,
                                reload_metadata=False)

    class VerificationTracker:
        node_verifications = 0
        metadata_verifications = 0

        @classmethod
        def fake_verify_node(cls, *args, **kwargs):
            cls.node_verifications += 1

        @classmethod
        def fake_verify_metadata(cls, *args, **kwargs):
            cls.metadata_verifications += 1

    with patch("nucypher.config.storages.ForgetfulNodeStorage.store_node_certificate",
               new=lambda *args, **kwargs: "do not store cert."):
        with patch("nucypher.characters.lawful.Ursula.verify_node", new=VerificationTracker.fake_verify_node):
            with patch("nucypher.network.nodes.FleetStateTracker.record_fleet_state", new=lambda *args, **kwargs: None):
                alice = config.produce(known_nodes=list(_ursulas)[:1],
                                       )
    # We started with one known_node and verified it.
    # TODO: Consider changing this - #1449
    assert VerificationTracker.node_verifications == 1

    with patch("nucypher.config.storages.ForgetfulNodeStorage.store_node_certificate",
               new=lambda *args, **kwargs: "do not store cert."):
        with patch("nucypher.characters.lawful.Ursula.verify_node", new=VerificationTracker.fake_verify_node):
            with patch("nucypher.network.nodes.Teacher.validate_metadata",
                       new=VerificationTracker.fake_verify_metadata):
                with patch('nucypher.characters.lawful.Alice.verify_from', new=lambda *args, **kwargs: None):
                    with patch('umbral.keys.UmbralPublicKey.from_bytes', NotAPublicKey.from_bytes):
                        with patch('nucypher.characters.lawful.load_pem_x509_certificate',
                                   new=lambda *args, **kwargs: NotACert()):
                            with patch('nucypher.crypto.signing.SignatureStamp.__call__', new=NotAPrivateKey.stamp):
                                with patch('umbral.signing.Signature.__bytes__', new=NotAPrivateKey.signature_bytes):
                                    started = time.time()
                                    alice.block_until_number_of_known_nodes_is(8, learn_on_this_thread=True, timeout=60)
                                    ended = time.time()
                                    elapsed = ended - started

    assert VerificationTracker.node_verifications == 1  # We have only verified the first Ursula.
    assert sum(isinstance(u, Ursula) for u in alice.known_nodes) < 20  # We haven't instantiated many Ursulas.
    assert elapsed < 8  # 8 seconds is still a little long to discover 8 out of 5000 nodes, but before starting the optimization that went with this test, this operation took about 18 minutes on jMyles' laptop.


@pytest.mark.slow()
def test_all_blockchain_ursulas_know_about_all_other_ursulas(blockchain_ursulas, agency):
    """
    Once launched, all Ursulas know about - and can help locate - all other Ursulas in the network.
    """
    token_agent, staking_agent, policy_agent = agency
    for address in staking_agent.swarm():
        for propagating_ursula in blockchain_ursulas[:1]:  # Last Ursula is not staking
            if address == propagating_ursula.checksum_address:
                continue
            else:
                assert address in propagating_ursula.known_nodes.addresses(), "{} did not know about {}". \
                    format(propagating_ursula, nickname_from_seed(address))


@pytest.mark.slow()
def test_blockchain_alice_finds_ursula_via_rest(blockchain_alice, blockchain_ursulas):
    # Imagine alice knows of nobody.
    blockchain_alice._Learner__known_nodes = FleetStateTracker()

    blockchain_alice.remember_node(blockchain_ursulas[0])
    blockchain_alice.learn_from_teacher_node()
    assert len(blockchain_alice.known_nodes) == len(blockchain_ursulas)

    for ursula in blockchain_ursulas:
        assert ursula in blockchain_alice.known_nodes


def test_alice_creates_policy_with_correct_hrac(idle_federated_policy):
    """
    Alice creates a Policy.  It has the proper HRAC, unique per her, Bob, and the label
    """
    alice = idle_federated_policy.alice
    bob = idle_federated_policy.bob

    assert idle_federated_policy.hrac() == keccak_digest(bytes(alice.stamp)
                                                         + bytes(bob.stamp)
                                                         + idle_federated_policy.label)


def test_alice_sets_treasure_map(enacted_federated_policy, federated_ursulas):
    """
    Having enacted all the policies of a PolicyGroup, Alice creates a TreasureMap and ...... TODO
    """
    enacted_federated_policy.publish_treasure_map(network_middleware=MockRestMiddleware())
    treasure_map_index = bytes.fromhex(enacted_federated_policy.treasure_map.public_id())
    treasure_map_as_set_on_network = list(federated_ursulas)[0].treasure_maps[treasure_map_index]
    assert treasure_map_as_set_on_network == enacted_federated_policy.treasure_map


def test_treasure_map_stored_by_ursula_is_the_correct_one_for_bob(federated_alice, federated_bob, federated_ursulas,
                                                                  enacted_federated_policy):
    """
    The TreasureMap given by Alice to Ursula is the correct one for Bob; he can decrypt and read it.
    """

    treasure_map_index = bytes.fromhex(enacted_federated_policy.treasure_map.public_id())
    treasure_map_as_set_on_network = list(federated_ursulas)[0].treasure_maps[treasure_map_index]

    hrac_by_bob = federated_bob.construct_policy_hrac(federated_alice.stamp, enacted_federated_policy.label)
    assert enacted_federated_policy.hrac() == hrac_by_bob

    hrac, map_id_by_bob = federated_bob.construct_hrac_and_map_id(federated_alice.stamp, enacted_federated_policy.label)
    assert map_id_by_bob == treasure_map_as_set_on_network.public_id()


def test_bob_can_retreive_the_treasure_map_and_decrypt_it(enacted_federated_policy, federated_ursulas):
    """
    Above, we showed that the TreasureMap saved on the network is the correct one for Bob.  Here, we show
    that Bob can retrieve it with only the information about which he is privy pursuant to the PolicyGroup.
    """
    bob = enacted_federated_policy.bob

    # Of course, in the real world, Bob has sufficient information to reconstitute a PolicyGroup, gleaned, we presume,
    # through a side-channel with Alice.

    # If Bob doesn't know about any Ursulas, he can't find the TreasureMap via the REST swarm:
    with pytest.raises(bob.NotEnoughTeachers):
        treasure_map_from_wire = bob.get_treasure_map(enacted_federated_policy.alice.stamp,
                                                      enacted_federated_policy.label)

    # Bob finds out about one Ursula (in the real world, a seed node)
    bob.remember_node(list(federated_ursulas)[0])

    # ...and then learns about the rest of the network.
    bob.learn_from_teacher_node(eager=True)

    # Now he'll have better success finding that map.
    treasure_map_from_wire = bob.get_treasure_map(enacted_federated_policy.alice.stamp,
                                                  enacted_federated_policy.label)

    assert enacted_federated_policy.treasure_map == treasure_map_from_wire


def test_treasure_map_is_legit(enacted_federated_policy):
    """
    Sure, the TreasureMap can get to Bob, but we also need to know that each Ursula in the TreasureMap is on the network.
    """
    for ursula_address, _node_id in enacted_federated_policy.treasure_map:
        assert ursula_address in enacted_federated_policy.bob.known_nodes.addresses()


@pytest.mark.skip("See Issue #1075")  # TODO: Issue #1075
def test_vladimir_illegal_interface_key_does_not_propagate(blockchain_ursulas):
    """
    Although Ursulas propagate each other's interface information, as demonstrated above,
    they do not propagate interface information for Vladimir.

    Specifically, if Vladimir tries to perform the most obvious imitation attack -
    propagating his own wallet address along with Ursula's information - the validity
    check will catch it and Ursula will refuse to propagate it and also record Vladimir's
    details.
    """
    ursulas = list(blockchain_ursulas)
    ursula_whom_vladimir_will_imitate, other_ursula = ursulas[0], ursulas[1]

    # Vladimir sees Ursula on the network and tries to use her public information.
    vladimir = Vladimir.from_target_ursula(ursula_whom_vladimir_will_imitate)

    # This Ursula is totally legit...
    ursula_whom_vladimir_will_imitate.verify_node(MockRestMiddleware(), accept_federated_only=True)

    learning_callers = []
    crosstown_traffic.decorator = crosstownTaskListDecoratorFactory(learning_callers)

    vladimir.network_middleware.propagate_shitty_interface_id(other_ursula, bytes(vladimir))

    # So far, Ursula hasn't noticed any Vladimirs.
    assert other_ursula.suspicious_activities_witnessed['vladimirs'] == []

    # ...but now, Ursula will now try to learn about Vladimir on a different thread.
    # We only passed one node (Vladimir)...
    learn_about_vladimir = learning_callers.pop()
    #  ...so there was only one learning caller in the queue (now none since we popped it just now).
    assert len(learning_callers) == 0

    # OK, so cool, let's see what happens when Ursula tries to learn about Vlad.
    learn_about_vladimir()

    # And indeed, Ursula noticed the situation.
    # She didn't record Vladimir's address.
    assert vladimir not in other_ursula.known_nodes

    # But she *did* record the actual Ursula's address.
    assert ursula_whom_vladimir_will_imitate in other_ursula.known_nodes

    # Furthermore, she properly marked Vladimir as suspicious.
    assert vladimir in other_ursula.suspicious_activities_witnessed['vladimirs']


@pytest.mark.skip("See Issue #1075")  # TODO: Issue #1075
def test_alice_refuses_to_make_arrangement_unless_ursula_is_valid(blockchain_alice,
                                                                  idle_blockchain_policy,
                                                                  blockchain_ursulas):
    target = list(blockchain_ursulas)[2]
    # First, let's imagine that Alice has sampled a Vladimir while making this policy.
    vladimir = Vladimir.from_target_ursula(target)

    message = vladimir._signable_interface_info_message()
    signature = vladimir._crypto_power.power_ups(SigningPower).sign(message)

    vladimir.substantiate_stamp(client_password=INSECURE_DEVELOPMENT_PASSWORD)
    vladimir._Teacher__interface_signature = signature

    class FakeArrangement:
        federated = False
        ursula = target

    vladimir.node_storage.store_node_certificate(certificate=target.certificate)

    with pytest.raises(vladimir.InvalidNode):
        idle_blockchain_policy.consider_arrangement(network_middleware=blockchain_alice.network_middleware,
                                                    arrangement=FakeArrangement(),
                                                    ursula=vladimir)


def test_alice_does_not_update_with_old_ursula_info(federated_alice, federated_ursulas):
    ursula = list(federated_ursulas)[0]
    old_metadata = bytes(ursula)

    # Alice has remembered Ursula.
    assert federated_alice.known_nodes[ursula.checksum_address] == ursula

    # But now, Ursula wants to sign and date her interface info again.  This causes a new timestamp.
    ursula._sign_and_date_interface_info()

    # Indeed, her metadata is not the same now.
    assert bytes(ursula) != old_metadata

    old_ursula = Ursula.from_bytes(old_metadata, federated_only=True)

    # Once Alice learns about Ursula's updated info...
    federated_alice.remember_node(ursula)

    # ...she can't learn about old ursula anymore.
    federated_alice.remember_node(old_ursula)

    new_metadata = bytes(federated_alice.known_nodes[ursula.checksum_address])
    assert new_metadata != old_metadata
