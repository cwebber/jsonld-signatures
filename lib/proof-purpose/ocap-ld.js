/**
 * Linked Data Signatures/Proofs
 *
 * @author Christopher Lemmer Webber
 *
 * @license BSD 3-Clause License
 * Copyright (c) 2018 Digital Bazaar, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of the Digital Bazaar, Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

'use strict';

const ocapBaseUri = 'https://example.org/ocap/v1#';

function prefixedOcapUri(suffix) {
  return ocapBaseUri + suffix;
}

// Vocabulary URIs
// TODO: It may be this isn't necessary since we have proofPurpose of
//
const CapbilityUri = prefixedOcapUri(
  'Capability');  // Capability, the type
const capbilityUri = prefixedOcapUri(
  'capability');  // capability, the property
const caveatUri = prefixedOcapUri(
  'caveat');
const invokerUri = prefixedOcapUri(
  'invoker');
const capabilityInvocationUri = prefixedOcapUri(
  'capabilityInvocation');
const capabilityDelegationUri = prefixedOcapUri(
  'capabilityDelegation');
const parentCapabilityUri = prefixedOcapUri(
  'parentCapability');
const invocationTargetUri = prefixedOcapUri(
  'invocationTarget');
const allowedActionUri = prefixedOcapUri(
  'allowedAction');

const proofUri = 'https://w3id.org/security#proof';
const proofPurposeUri = 'https://w3id.org/security#proofPurpose';

const creatorUri = 'http://purl.org/dc/terms/creator';

const ProofPurpose = require('./ProofPurpose');

function getOneOrDie(array, errorMessage = "Expected an array of size 1") {
  if (!Array.isArray(array) || array.length != 1) {
    throw new Error(errorMessage);
  }
  return array[0];
}

// Check if obj is an object that is of length 1 and has an @id,
// and only an @id
function idOnlyObject(obj) {
  return obj.length === 1 && obj['@id'] != undefined;
}

module.exports = class CapabilityInvocationProofPurpose extends ProofPurpose {
  constructor(injector) {
    super(injector);
    this.uri = capabilityInvocationUri;
  }

  // TODO: We might need to add some sort of way to query system state, eg
  //   a blockchain may be loaded with a different state depending on when
  //   this is called
  // Arguments:
  //  - caveat: Expanded version of the caveat document
  //  - expandedInvocation: Expanded version of the ocap invocation this is
  //    called from
  async verifyCaveat(caveat, expandedInvocation, caveatVerifiers) {
    const caveatType = getOneOrDie(caveat["@type"],
                                   'caveat must not have more than one value for @type');
    // FIXME: Throw an error if caveatVerifiers doesn't have an appropriate
    //   verifier
    // Retrieve the verifier for this type
    const caveatVerifier = caveatVerifiers[caveatType];
    // Run the caveat verifier, which will raise an exception if the
    // verification fails
    return caveatVerifier(caveat, expandedInvocation);
  }

  // Arguments:
  //  - document: An already-expanded version of the invocation document
  //    this proof is attached to
  //  - proof: An already-expanded version of the proof we are checking
  //
  // ppOptions keywords:
  //  - expectedTarget: the target we expect this capability to apply to.
  //  - caveatVerifiers: a hashmap of caveat URIs to procedures which
  //    verify those caveats.  The caveat-verifying procedures should take
  //    two arguments: the caveat being verified, and the expanded invocation
  //    document.
  async verify(document, proof, ppOptions) {
    const cap = getOneOrDie(proof[capabilityUri]);
    const invokers = await getCapInvokers(cap, ppOptions);
    const creator = getOneOrDie(proof[creatorUri]);
    const target = await getCapTarget(cap, ppOptions);
    const expectedTarget = ppOptions.expectedTarget;

    return (invokers.includes(creator) && // proof stamped by authorized invoker
            await this.targetMatchesExpected(target, expectedTarget) &&
            await verifyCap(cap, ppOptions, injector.jsonld) &&
            await this.verifyCaveats(document, proof, ppOptions));
  }

  async targetMatchesExpected(target, expectedTarget) {
    "TODO"
  }

  async verifyCaveats(invocation, proof, ppOptions) {
    const caveats = await this.gatherCapCaveats(
      getOneOrDie(proof[capabilityUri]));
    const caveatRegistry = ppOptions['caveatRegistry'] || defaultCaveatRegistry;
    for (const caveat of caveats) {
      const caveatType = getOneOrDie(caveat['@type']);
      if (!caveatType in caveatRegistry) {
        throw new Error("caveat handler not found for caveat type: " + caveatType);
      }
      const caveatChecker = caveatRegistry[caveatType];
      if (!await caveatChecker(caveat, invocation, proof, ppOptions)) {
        return false;
      }
      return true;
    }
  }
}

const defaultCaveatRegistry = "TODO";

// The default do-nothing check for if things are revoked
async function noopRevocationChecker(cap, ppOptions) {
  return true;
}

// TODO: Maybe convert this to a non-recursive version that iterates through
//   the cap chain as an array instead
module.exports = class CapabilityDelegateProofPurpose extends ProofPurpose {
  constructor(injector) {
    super(injector);
    self.uri = capabilityDelegationUri;
  }

  async verify(document, proof, ppOptions) {
    const checkIfRevoked = ppOptions['revocationChecker'] || noopRevocationChecker;
    // Revoked?  Then nope...
    if (await checkIfRevoked(document, ppOptions)) {
      return false;
    }
    // No parentCapability?  Delegation doesn't apply to the target, so nope...
    if (!(parentCapabilityUri in document)) {
      return false;
    }
    const parent = getOneOrDie(document[parentCapabilityUri]);
    // Not a member of the parent invokers?  Then nope...
    const creator = getOneOrDie(proof[creatorUri]);
    const invokers = await capGetInvokers(parent);
    if (!invokers.includes(creator)) {
      return false;
    }
    // Is the parent an invalid cap?
    if (!await verifyCap(cap, ppOptions, this.injector.use('jsonld'))) {
      return false;
    }
    // Ok, we're good!
    return true;
  }
}

async function verifyCap(cap, ppOptions, jsonld) {
  if (!(parentCapabilityUri in cap)
      && capabilityDelegationUri in cap) {
    // It's the toplevel capability, which means it's valid
    return true;
  } else {
    // Otherwise, we have to check the signature
    return jsonld.verify(cap, {proofPurpose: CapabilityDelegateProofPurpose,
                               ppOptions: ppOptions});
  }
}

