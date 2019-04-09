/*
 * Copyright (c) 2019 ARM Limited and affiliates.
 * SPDX-License-Identifier: MIT
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
