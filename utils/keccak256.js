var createKeccakHash = require('keccak')

module.exports = function keccak256 (inp) {
  return createKeccakHash('keccak256').update(inp.toString()).digest('hex')
}
