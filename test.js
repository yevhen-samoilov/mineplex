const { mpapi } = require('index.js');

const mnemonic = mpapi.crypto.generateMnemonic();

console.log(mpapi.crypto.validateMnemonic('1report cloth clip excite simple coconut athlete business learn reopen suit similar faculty spin shell'));
const keys = mpapi.crypto.generateKeys(mnemonic);
console.log(keys)
