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
const capabilityDelegateUri = prefixedOcapUri(
  'capabilityDelegate');
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

module.exports = class InvokeCapabilityProofPurpose extends ProofPurpose {
  constructor(injector, {caveatVerifiers: defaultCaveatVerifiers}) {
    super(injector);
    this.algorithmUri = capabilityInvocationUri;
    this.caveatVerifiers = caveatVerifiers;
  }

  // TODO: We might need to add some sort of way to query system state, eg
  //   a blockchain may be loaded with a different state depending on when
  //   this is called
  // Arguments:
  //  - caveat: Expanded version of the caveat document
  //  - expandedInvocation: Expanded version of the ocap invocation this is
  //    called from
  async verifyCaveat(caveat, expandedInvocation) {
    const caveatType = getOneOrDie(caveat["@type"],
                                   'caveat must not have more than one value for @type');
    // FIXME: Throw an error if caveatVerifiers doesn't have an appropriate
    //   verifier
    // Retrieve the verifier for this type
    const caveatVerifier = this.caveatVerifiers[caveatType];
    // Run the caveat verifier, which will raise an exception if the
    // verification fails
    return caveatVerifier(caveat, expandedInvocation);
  }

  // Get the capability chain as a list of fully expanded json-ld documents,
  // starting with the root capability document and working from there.
  async getCapChain(ocapProof) {
    // Prevent cyclical fetching.  Not a problem when capability documents
    // are embedded, but definitely a problem when we fetch.
    // TODO: Is it even a good idea to ever fetch these documents?  In the
    //   case of a capability chain, it seems like best practice to always
    //   embed the full chain.
    const fetched = new Set();
    let capChain = [];
    const safeFetchCapability = async (capUri) => {
      if (fetched.has(capUri)) {
        throw new Error("Cyclical capability chain detected");
      }
      fetched.add(capUri);
      return await this.fetchCapability(capUri);
    };

    // The next capability to process.  We start from the proof and we
    // move upward until there are no more parentCapability objects.
    let cap = getOneOrDie(ocapProof[capabilityUri]);
    while (cap) {
      // TODO: For now, we're only re-fetching the capability document if
      //   there's only an @id
      if (idOnlyObject(cap)) {
        cap = await safeFetchCapability(cap['@id']);
      }
      capChain.push(cap);
      if (parentCapabilityUri in cap) {
        cap = getOneOrDie(cap[parentCapability]);
      } else {
        cap = false;
      }
    }
    return capChain;
  }

  async verify(document, proof, ppOptions) {
    const capChain = await getCapChain(proof);
    const {expectedTarget} = ppOptions;
    const capRoot = _.head(capChain);
    const capTail = _.tail(capChain);

    // The target is what will be invoked against.
    const target = await this.fetchTarget(
      capRoot[invocationTargetUri]);

    // Is this the target we thought it would be?  (Probably
    // self.expectedTarget)
    this.assertExpectedTarget(target);

    // The initial set of currently authorized cryptographic materials
    // come from the capabilityDelegate field of the target
    const currentlyAuthorized = target[capabilityDelegateUri];

    const ensureCapAuthorized = async (cap) => {
      // cyclical dependency... yuck
      const jldsigs = require('../jsonld-signatures');
      const capProofs = cap[proofUri] || [];
      // Filter capProofs down to just the ones with proofPurpose of
      // capabilityDelegate
      const grantCapProofs = _.filter(
        capProofs,
        (proof) => {
          return proof[proofPurposeUri][0] === capabilityDelegateUri;
        });

      // Well actually, we only want there to be one grantCapProof.  If there
      // were more than one, that would be a mess.
      const grantCapProof = getOneOrDie(grantCapProofs);
      // Annnnnnd, that capability granting cap *better* have a creator that
      // matches one of the currentlyAuthorized we have
      const grantProofCreator = getOneOrDie(grantCapProof[creatorUri]);
      // FIXME: Right now we're only comparing based on the ids.  However
      //   it's more than feasible and reasonable (maybe even safer!) in this
      //   system to include keys inline, possibly even with no @id given.  As
      //   long as it's signed with that same key it should be fine.
      //   But in order to determine that such cryptographic material was the
      //   "same", we would have to compare on the normalized version.
      if (! '@id' in grantProofCreator) {
        throw new Error('Creator must have @id');
      }

      const foundAuthorized = _.find(
        currentlyAuthorized,
        (candidate) => {
          candidate['@id'] === grantProofCreator['@id']});

      if (! foundAuthorized) {
        throw new Error(
          'Capability document has no proofPurpose signed by an authorized entity');
      }

      // Okay, we've ensured that there's a grantCapability proofPurpose with
      // an entity qualified to grant it... let's run the verification algorithm
      return await jldsigs.verify(
        cap,
        {proofPurpose: new GrantCapabilityProofPurpose(this.injector)});
    };

    // The number of authorized invokers grows from each capability chain
    // document
    const extendAuthorized = async (cap) => {
      if (! invokerUri in cap) {
        throw new Error("Having an empty invoker list doesn't make sense");
      }
      // Again.. I'm not sure what the right approach is re: re-fetching
      // these documents or not.  For now, shunting that to a method.
      for (const invoker of cap[invokerUri]) {
        currentlyAuthorized.push(await this.fetchInvoker(invoker));
      }
    }

    ////// Root stuff starts here
    // We treat the root slightly differently because it's required to
    // have certain information that "sets up" the rest of the chain.

    // Make sure the root cap is signed by the target
    ensureCapAuthorized(capRoot);

    // Next, let's determine what the initial actions are
    //   (These may be restricted as the chain goes on)
    const allowedActions = new Set(_.map(
      (a) => {return a['@id'];},
      rootCap[allowedActionUri] || []));
    if (allowedActions.length === 0) {
      throw new Error('root capability allowedAction must not be empty');
    }

    // Extract the initial grantees
    await extendAuthorized(capRoot);
    ////// Root stuff ends here

    // Now for everything else!  It's similar to the root.
    for (const cap in capTail) {
      // Ensure it's authorized
      ensureCapAuthorized(cap);

      // Are actions specified?  Then we should narrow the allowed set of
      // actions.
      // We should also make sure that there aren't any actions that weren't
      // in the set before.  No sneaking in new actions!
      if ((cap[allowedActionUri] || []).length !== 0) {
        let newActions = new Set();
        for (const action in cap[allowedActionUri]) {
          if (! '@id' in action) {
            throw new Error('allowedAction entries must have an @id');
          }
          const actionId = action['@id'];
          if (! allowedActions.has(actionId)) {
            throw new Error('Actions can only be restricted in a capability chain');
          }
          newActions.add(actionId);
        }
        // Replace actions with new restricted subset.
        allowedActions = newActions;
      }

      // Next let's extend the authorized list
      extendAuthorized(cap);
    }

    // Okay, now that we've validated the list of authorized entities,
    // is the creator of this signature actually amongst them?
    if (! creatorUri in proof) {
      throw new Error('invocation proof creator field is mandatory');
    }

    const creator = getOneOrDie(proof[creatorUri]);
    if (! '@id' in creator) {
      // Again, this might not need to be true.  It may be that we should
      // be able to ensure that the creator is
      throw new Error('creator field must have @id');
    }
    const invocationProofByAuthorized = _.filter(
      currentlyAuthorized,
      (candidate) => {
        candidate['@id'] === creator['@id'];
      })
    if (! invocationProofByAuthorized) {
      throw new Error('invocation not signed by an authorized entity');
    }

    // Also this invocation's type should be within the allowedActions
    // TODO: Do we want to support the document having more than one
    //   "action" type?
    const documentType = getOneOrDie(document['@type']);
    // Let's make sure the type is amongst the allowed actions
    if (! allowedActions.has(documentType)) {
      throw new Error('invocation @type not in capability chain\'s allowedActions');
    }

    // What about caveats, are those valid?
    for (const cap in capChain) {
      for (const caveat in (cap[caveatUri] || [])) {
        if (! this.verifyCaveat(caveat)) {
          throw new Error('caveat did not pass validation');
        }
      }
    }

    // Okay... seems like we're good...
    return true;
  }

}

module.exports = class GrantCapabilityProofPurpose extends ProofPurpose {
  constructor(injector) {
    super(injector);
    this.authorizedGranters = authorizedGranters;
  }

  async verify(document, proof, ppOptions) {
    throw new Error('TODO');
  }
}
