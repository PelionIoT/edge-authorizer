'use strict'

const RingState = require('./partitioner').RingState
const HashRing = require('./partitioner').HashRing

class RulePartitioner {
    constructor(nodeID) {
        this.nodeID = nodeID
        this.hashRing = new HashRing(nodeID)

        this.updateRelays(new Set([ ]))
    }

    updateRelays(reachableRelaySet) {
        let tokens = { }

        for(let nodeID of reachableRelaySet) {
            tokens[nodeID] = {
                version: 0,
                tokens: [ this.hashRing.getToken(nodeID) ]
            }
        }

        tokens[this.nodeID] = {
            version: 0,
            tokens: [ this.hashRing.getToken(this.nodeID) ]
        }

        this.hashRing.getRingState().setTokens(tokens)
    }

    getRuleExecutor(ruleID) {
        return this.hashRing.getPreferenceList(ruleID).sort()[0]
    }

    isExecutedByMe(ruleID) {
        return this.getRuleExecutor(ruleID) == this.nodeID
    }
}

module.exports = RulePartitioner
