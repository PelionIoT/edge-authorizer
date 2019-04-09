'use strict'

const bcrypt = require('bcrypt-nodejs')
const jwt = require('jsonwebtoken')
const uuid = require('node-uuid')

function makeUUIDHex() {
    var uuidBuffer = new Buffer(16);

    uuid.v4(null, uuidBuffer, 0);

    return uuidBuffer.toString('hex');
}

class WigWagAuthorizer {
    constructor(options) {
        this.relayID = options.relayID
        this.relayPrivateKey = options.relayPrivateKey
        this.relayPublicKey = options.relayPublicKey
        this.jwtSecret = makeUUIDHex()
        this.ddb = options.ddb
    }
    
    _getUserCredentials(email) {
        return this.ddb.cloud.get('wigwag.users.' + email).then(function(result) {
            if(result == null || result.siblings.length == 0) {
                return null
            }
            
            try {
                return JSON.parse(result.siblings[0])
            }
            catch(error) {
                return null
            }
        })
    }
    
    _getAccountRelays() {
        return this.ddb.cloud.get('wigwag.relays').then(function(result) {
            if(result == null || result.siblings.length == 0) {
                return new Map()
            }
            
            let mergedParsedRelayMap = new Map()
            
            for(let sibling of result.siblings) {
                try {
                    let parsedRelayMap = JSON.parse(sibling)
                    
                    for(let relayID in parsedRelayMap) {
                        mergedParsedRelayMap.set(relayID, parsedRelayMap[relayID])
                    }
                }
                catch(error) {
                }
            }
            
            return mergedParsedRelayMap
        })
    }
    
    isRelayAuthorized(relayID) {
        return this._getAccountRelays().then((relayMap) => {
            return relayMap.has(relayID)
        })
    }
    
    generateAccessToken(username, password) {
        return this._getUserCredentials(username).then((credentials) => {
            if(credentials == null) {
                return null
            }
            
            let hashedPassword = credentials.hashedPassword
               
            if(bcrypt.compareSync(password, hashedPassword)) {
                // identity needs a password to be authenticated it provided one but it is not correct
                let token

                if(this.relayPrivateKey && this.relayPublicKey) {
                    token = jwt.sign({ associationID: makeUUIDHex(), issuerID: this.relayID }, this.relayPrivateKey, { algorithm: 'RS256' })
                }
                else {
                    token = jwt.sign({ associationID: makeUUIDHex(), issuerID: this.relayID }, this.jwtSecret)
                }
                
                return token
            }
            
            return null
        })
    }

    generateAccessTokenNoCredentials() {
        try {
            let token

            if(this.relayPrivateKey && this.relayPublicKey) {
                token = jwt.sign({ associationID: makeUUIDHex(), issuerID: this.relayID }, this.relayPrivateKey, { algorithm: 'RS256' })
            }
            else {
                token = jwt.sign({ associationID: makeUUIDHex(), issuerID: this.relayID }, this.jwtSecret)
            }
                    
            return Promise.resolve(token)
        }
        catch(error) {
            return Promise.reject(error)
        }
    }
    
    decodeAccessToken(accessToken) {
        let decodedToken = jwt.decode(accessToken)
        let issuerID = decodedToken.issuerID
        
        if(!issuerID) {
            return Promise.reject(new Error('Invalid token'))
        }
        
        if(issuerID == this.relayID) {
            try {
                if(this.relayPrivateKey && this.relayPublicKey) {
                    return Promise.resolve(jwt.verify(accessToken, this.relayPublicKey, { algorithms: [ 'RS256' ] }))
                }
                else {
                    return Promise.resolve(jwt.verify(accessToken, this.jwtSecret))
                }
            }
            catch(error) {
                return Promise.reject(new Error('Invalid token'))
            }
        }
       
        return this._getAccountRelays().then((relayMap) => {
            if(!relayMap.has(issuerID)) {
                throw new Error('Invalid token')
            }
            
            let issuerPublicKey = relayMap.get(issuerID)
            
            try {
                return jwt.verify(accessToken, issuerPublicKey, { algorithms: [ 'RS256' ] })
            }
            catch(error) {
                throw new Error('Invalid token')
            }
        })
    }

    generateRelayIdentityToken() {
        return jwt.sign({ issuerID: this.relayID }, this.relayPrivateKey, { algorithm: 'RS256' })
    }
}

module.exports = WigWagAuthorizer