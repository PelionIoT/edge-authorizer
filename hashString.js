'use strict'

const bcrypt = require('bcrypt-nodejs')
const process = require('process')

if(process.argv.length < 3) {
    console.log('Usage: \n    hashString STRING')
}
else {
    console.log(bcrypt.hashSync(process.argv[2]))
}