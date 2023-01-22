if (typeof XMLHttpRequest == "undefined") XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
//main.js
if (typeof require == "undefined") require = require("buffer/").Buffer;
const defaultProvider = "https://web-wallet.mineplex.io/api/2.0/",
  library = {
    bs58check: require('bs58check'),
    sodium: require('sodium-universal'),
    bip39: require('bip39'),
    pbkdf2: require('pbkdf2'),
  },
  prefix = {
    mp1: new Uint8Array([5, 183, 099]),
    mp2: new Uint8Array([5, 183, 102]),
    mp3: new Uint8Array([5, 183, 104]),
    KT: new Uint8Array([2,90,121]),
    
    
    edpk: new Uint8Array([13, 15, 37, 217]),
    edsk2: new Uint8Array([13, 15, 58, 7]),
    spsk: new Uint8Array([17, 162, 224, 201]),
    p2sk: new Uint8Array([16,81,238,189]),
    
    sppk: new Uint8Array([3, 254, 226, 86]),
    p2pk: new Uint8Array([3, 178, 139, 127]),
    
    edsk: new Uint8Array([43, 246, 78, 7]),
    edsig: new Uint8Array([9, 245, 205, 134, 18]),
    spsig1: new Uint8Array([13, 115, 101, 19, 63]),
    p2sig: new Uint8Array([54, 240, 44, 52]),
    sig: new Uint8Array([4, 130, 43]),
    
    Net: new Uint8Array([87, 82, 0]),
    nce: new Uint8Array([69, 220, 169]),
    b: new Uint8Array([1,52]),
    o: new Uint8Array([5, 116]),
    Lo: new Uint8Array([133, 233]),
    LLo: new Uint8Array([29, 159, 109]),
    P: new Uint8Array([2, 170]),
    Co: new Uint8Array([79, 179]),
    id: new Uint8Array([153, 103]),
},
  watermark = {
    block: new Uint8Array([1]),
    endorsement: new Uint8Array([2]),
    generic: new Uint8Array([3]),
  },
utility = {
  totez: m => parseInt(m) / 1000000,
  mutez: function (mp) {
    let r = Number(Number(mp.toFixed(6) * 1000000).toFixed());
    if (r > 4294967296) r = r.toString();
    return r;
  },
  b58cencode: function (payload, prefix) {
    const n = new Uint8Array(prefix.length + payload.length);
    n.set(prefix);
    n.set(payload, prefix.length);
    return library.bs58check.encode(new Buffer(n, 'hex'));
  },
  b58cdecode: (enc, prefix) => library.bs58check.decode(enc).slice(prefix.length),
  buf2hex: function (buffer) {
    const byteArray = new Uint8Array(buffer), hexParts = [];
    for (let i = 0; i < byteArray.length; i++) {
      let hex = byteArray[i].toString(16);
      let paddedHex = ('00' + hex).slice(-2);
      hexParts.push(paddedHex);
    }
    return hexParts.join('');
  },
  hex2buf : function(hex){
      return new Uint8Array(hex.match(/[\da-f]{2}/gi).map(function (h) {
        return parseInt(h, 16)
      }));
  },
  hexNonce: function (length) {
    var chars = '0123456789abcedf';
    var hex = '';
    while (length--) hex += chars[(Math.random() * 16) | 0];
    return hex;
  },
  mergebuf : function(b1,b2){
    var r = new Uint8Array(b1.length+b2.length);
    r.set(b1);
    r.set(b2, b1.length);
    return r;
  },
  sexp2mic: function me(mi) {
    mi = mi.replace(/(?:@[a-z_]+)|(?:#.*$)/mg, '')
      .replace(/\s+/g, ' ')
      .trim();
    if (mi.charAt(0) === "(") mi = mi.slice(1, -1);
    let pl = 0;
    let sopen = false;
    let escaped = false;
    let ret = {
      prim: '',
      args: []
    };
    let val = "";
    for (let i = 0; i < mi.length; i++) {
      if (escaped) {
        val += mi[i];
        escaped = false;
        continue;
      }
      else if ((i === (mi.length - 1) && sopen === false) || (mi[i] === " " && pl === 0 && sopen === false)) {
        if (i === (mi.length - 1)) val += mi[i];
        if (val) {
          if (val === parseInt(val).toString()) {
            if (!ret.prim) return {"int": val};
            else ret.args.push({"int": val});
          } else if (ret.prim) {
            ret.args.push(me(val));
          } else {
            ret.prim = val;
          }
          val = '';
        }
        continue;
      }
      else if (mi[i] === '"' && sopen) {
        sopen = false;
        if (!ret.prim) return {'string': val};
        else ret.args.push({'string': val});
        val = '';
        continue;
      }
      else if (mi[i] === '"' && !sopen && pl === 0) {
        sopen = true;
        continue;
      }
      else if (mi[i] === '\\') escaped = true;
      else if (mi[i] === "(") pl++;
      else if (mi[i] === ")") pl--;
      val += mi[i];
    }
    return ret;
  },
  mic2arr: function me2(s) {
    let ret = [];
    if (s.hasOwnProperty("prim")) {
      if (s.prim === "Pair") {
        ret.push(me2(s.args[0]));
        ret = ret.concat(me2(s.args[1]));
      } else if (s.prim === "Elt") {
        ret = {
          key: me2(s.args[0]),
          val: me2(s.args[1])
        };
      } else if (s.prim === "True") {
        ret = true
      } else if (s.prim === "False") {
        ret = false;
      }
    } else {
      if (Array.isArray(s)) {
        let sc = s.length;
        for (let i = 0; i < sc; i++) {
          let n = me2(s[i]);
          if (typeof n.key !== 'undefined') {
            if (Array.isArray(ret)) {
              ret = {
                keys: [],
                vals: [],
              };
            }
            ret.keys.push(n.key);
            ret.vals.push(n.val);
          } else {
            ret.push(n);
          }
        }
      } else if (s.hasOwnProperty("string")) {
        ret = s.string;
      } else if (s.hasOwnProperty("int")) {
        ret = parseInt(s.int);
      } else {
        ret = s;
      }
    }
    return ret;
  },
  ml2mic: function me(mi) {
    let ret = [], inseq = false, seq = '', val = '', pl = 0, bl = 0, sopen = false, escaped = false;
    for (let i = 0; i < mi.length; i++) {
      if (val === "}" || val === ";") {
        val = "";
      }
      if (inseq) {
        if (mi[i] === "}") {
          bl--;
        } else if (mi[i] === "{") {
          bl++;
        }
        if (bl === 0) {
          let st = me(val);
          ret.push({
            prim: seq.trim(),
            args: [st]
          });
          val = '';
          bl = 0;
          inseq = false;
        }
      }
      else if (mi[i] === "{") {
        bl++;
        seq = val;
        val = '';
        inseq = true;
        continue;
      }
      else if (escaped) {
        val += mi[i];
        escaped = false;
        continue;
      }
      else if ((i === (mi.length - 1) && sopen === false) || (mi[i] === ";" && pl === 0 && sopen == false)) {
        if (i === (mi.length - 1)) val += mi[i];
        if (val.trim() === "" || val.trim() === "}" || val.trim() === ";") {
          val = "";
          continue;
        }
        ret.push(mpapi.utility.ml2mpjson(val));
        val = '';
        continue;
      }
      else if (mi[i] === '"' && sopen) sopen = false;
      else if (mi[i] === '"' && !sopen) sopen = true;
      else if (mi[i] === '\\') escaped = true;
      else if (mi[i] === "(") pl++;
      else if (mi[i] === ")") pl--;
      val += mi[i];
    }
    return ret;
  },
  formatMoney: function (n, c, d, t) {
    var c = isNaN(c = Math.abs(c)) ? 2 : c,
      d = d === undefined ? "." : d,
      t = t === undefined ? "," : t,
      s = n < 0 ? "-" : "",
      i = String(parseInt(n = Math.abs(Number(n) || 0).toFixed(c))),
      j = (j = i.length) > 3 ? j % 3 : 0;
    return s + (j ? i.substr(0, j) + t : "") + i.substr(j).replace(/(\d{3})(?=\d)/g, "$1" + t) + (c ? d + Math.abs(n - i).toFixed(c).slice(2) : "");
  }
},
//TODO: Add p256 and secp256k1 cryptographay
crypto = {
  extractKeys : function(sk){
    const pref = sk.substr(0,4);
    switch(pref){
      case "edsk":
        if (sk.length == 98){
          const out = new Buffer(20);
          library.sodium.crypto_generichash(out, utility.b58cdecode(sk, prefix.edsk).slice(32))

          return {
            pk : utility.b58cencode(utility.b58cdecode(sk, prefix.edsk).slice(32), prefix.edpk),
            pkh : utility.b58cencode(out, prefix.mp1),
            sk : sk
          };
        } else if (sk.length == 54) { //seed
          const seed = utility.b58cdecode(sk, prefix.edsk2);
          const privateKey = new Buffer(library.sodium.crypto_sign_SECRETKEYBYTES);
          const publicKey = new Buffer(library.sodium.crypto_sign_PUBLICKEYBYTES);
          library.sodium.crypto_sign_seed_keypair(publicKey, privateKey, seed);

          const out = new Buffer(20);
          library.sodium.crypto_generichash(out, publicKey)

          return {
            sk: utility.b58cencode(privateKey, prefix.edsk),
            pk: utility.b58cencode(publicKey, prefix.edpk),
            pkh: utility.b58cencode(out, prefix.mp1),
          };
        }
      break;
      default:
        return false;
      break;
    }
  },
  generateMnemonic: () => library.bip39.generateMnemonic(160),
  validateMnemonic: (m) => library.bip39.validateMnemonic(m),
  checkAddress: function (a) {
    try {
      utility.b58cdecode(a, prefix.mp1);
      return true;
    }
    catch (e) {
      return false;
    }
  },
  generateKeysNoSeed: function () {
    const privateKey = new Buffer(library.sodium.crypto_sign_SECRETKEYBYTES);
    const publicKey = new Buffer(library.sodium.crypto_sign_PUBLICKEYBYTES);
    library.sodium.crypto_sign_keypair(publicKey, privateKey);

    const out = new Buffer(20);
    library.sodium.crypto_generichash(out, publicKey)

    return {
      sk: utility.b58cencode(privateKey, prefix.edsk),
      pk: utility.b58cencode(publicKey, prefix.edpk),
      pkh: utility.b58cencode(out, prefix.mp1),
    };
  },
  generateKeys: function (m, p) {
    const seed = library.bip39.mnemonicToSeedSync(m, p).slice(0, 32);
    const privateKey = new Buffer(library.sodium.crypto_sign_SECRETKEYBYTES);
    const publicKey = new Buffer(library.sodium.crypto_sign_PUBLICKEYBYTES);
    library.sodium.crypto_sign_seed_keypair(publicKey, privateKey, seed);

    const out = new Buffer(20);
    library.sodium.crypto_generichash(out, publicKey);

    return {
      mnemonic: m,
      passphrase: p,
      sk: utility.b58cencode(privateKey, prefix.edsk),
      pk: utility.b58cencode(publicKey, prefix.edpk),
      pkh: utility.b58cencode(out, prefix.mp1),
    };
  },
  generateKeysFromSeedMulti: function (m, p, n) {
    n /= (256 ^ 2);
    const s = library.bip39.mnemonicToSeedSync(m, library.pbkdf2.pbkdf2Sync(p, n.toString(36).slice(2), 0, 32, 'sha512').toString()).slice(0, 32);
    const kp = library.sodium.crypto_sign_seed_keypair(s);
    return {
      mnemonic: m,
      passphrase: p,
      n: n,
      sk: utility.b58cencode(kp.privateKey, prefix.edsk),
      pk: utility.b58cencode(kp.publicKey, prefix.edpk),
      pkh: utility.b58cencode(library.sodium.crypto_generichash(20, kp.publicKey), prefix.mp1),
    };
  },
  sign: function (bytes, sk, wm) {
    var bb = utility.hex2buf(bytes);
    if (typeof wm != 'undefined') bb = utility.mergebuf(wm, bb);

    const out = new Buffer(32);
    library.sodium.crypto_generichash(out, bb)

    const sig = new Buffer(library.sodium.crypto_sign_BYTES);
    library.sodium.crypto_sign_detached(sig, out, utility.b58cdecode(sk, prefix.edsk));
    const edsig = utility.b58cencode(sig, prefix.edsig);
    const sbytes = bytes + utility.buf2hex(sig);
    return {
      bytes: bytes,
      sig: sig,
      edsig: edsig,
      sbytes: sbytes,
    }
  },
  verify: function (bytes, sig, pk) {
    return library.sodium.crypto_sign_verify_detached(sig, utility.hex2buf(bytes), utility.b58cdecode(pk, prefix.edpk));
  },
};
node = {
  activeProvider: defaultProvider,
  debugMode: false,
  async: true,
  setDebugMode: function (t) {
    node.debugMode = t;
  },
  setProvider: function (u) {
    node.activeProvider = u;
  },
  resetProvider: function () {
    node.activeProvider = defaultProvider;
  },
  query: function (e, o, t) {
    if (typeof o === 'undefined') {
      if (typeof t === 'undefined') {
        t = "GET";
      } else 
        o = {};
    } else {
      if (typeof t === 'undefined')
        t = 'POST';
    }
    return new Promise(function (resolve, reject) {
      const http = new XMLHttpRequest();
      http.open(t, node.activeProvider + e, node.async);
      http.onload = function () {
        if (http.status === 200) {
          if (node.debugMode)
            console.log(http.status, e, o, http.responseText);
          if (http.responseText) {
            let r = JSON.parse(http.responseText);
            if (r === null)
              resolve(r);
            else if (typeof r.error !== 'undefined') {
              reject(r.error);
            } else {
              if (typeof r.ok !== 'undefined') r = r.ok;
              resolve(r);
            }
          } else {
            reject("Empty response returned");
          }
        } else {
          if (node.debugMode)
            console.log(http.status, e, o, http.responseText);
          reject(http.responseText);
        }
      };
      http.onerror = function () {
        reject(http.statusText);
      };
      if (t == 'POST'){
        http.setRequestHeader("Content-Type", "application/json");
        http.send(JSON.stringify(o));        
      } else {
        http.send();
      }
    });
  }
},
  rpc = {
    account: function (keys, amount, spendable, delegatable, delegate, fee) {
      const operation = {
        "kind": "origination",
        "fee": fee.toString(),
        "managerPubkey": keys.pkh,
        "balance": utility.mutez(amount).toString(),
        "spendable": (typeof spendable !== "undefined" ? spendable : true),
        "delegatable": (typeof delegatable !== "undefined" ? delegatable : true),
        "delegate": (typeof delegate !== "undefined" ? delegate : keys.pkh),
      };
      return rpc.sendOperation(keys.pkh, operation, keys);
    },
    getPlexBalance: function (mp1, block = 'head') {
      return node.query(`/chains/main/blocks/${block}/context/contracts/${mp1}/balance`).then(function (r) {
        return r;
      });
    },
    getMineBalance: function (mp1, block = 'head') {
      return node.query(`/chains/main/blocks/${block}/context/contracts/${mp1}/mine_balance`).then(function (r) {
        return r;
      });
    },
    getConstants: function (block = 'head') {
      return node.query(`/chains/main/blocks/${block}/context/constants`).then(function(c){
        if (c) return c;
        return false;
      }).catch(function(){return false});
    },
    getDelegate: function (mp1, block = 'head') {
      return node.query(`/chains/main/blocks/${block}/context/contracts/${mp1}/delegate`).then(function(r){
        if (r) return r;
        return false;
      }).catch(function(){return false});
    },
    getDelegateInfo: function (mp1, block = 'head') {
      return node.query(`/chains/main/blocks/${block}/context/delegates/${mp1}`).then(function(r){
        if (r) return r;
        return false;
      }).catch(function(){return false});
    },
    getMempoolOperations: function () {
      return node.query('/chains/main/mempool/pending_operations').then(function(r){
        if (r) return r;
        return false;
      }).catch(function(){return false});
    },
    getDelegatedAddresses: function (mp1, block = 'head') {
      return node.query(`/chains/main/blocks/${block}/context/delegates/${mp1}/delegated_contracts`).then(function(r){
        if (r) return r;
        return false;
      }).catch(function(){return false});
    },
    getOwnStakingMineBalance: function (mp1, block = 'head') {
      return node.query(`/chains/main/blocks/${block}/context/delegates/${mp1}/balance`).then(function(r){
        if (r) return r;
        return false;
      }).catch(function(){return false});
    },
    getDelegatedBalance: function (mp1, block = 'head') {
      return node.query(`/chains/main/blocks/${block}/context/delegates/${mp1}/delegated_balance`).then(function(r){
        if (r) return r;
        return false;
      }).catch(function(){return false});
    },
    getStakingMineBalance: function (mp1, block = 'head') {
      return node.query(`/chains/main/blocks/${block}/context/delegates/${mp1}/staking_balance`).then(function(staking_balance){
        return staking_balance;
      }).catch(function(){return false});
    },
    getAllActiveDelegates: function (block = 'head') {
      return node.query(`/chains/main/blocks/${block}/context/delegates?active=true`).then(function(delegates){
        return delegates
      }).catch(function(){ return false });
    },
    getBlockBakingRights: function (block = 'head', maxPriority = 999) {
      return node.query(`/chains/main/blocks/head/helpers/baking_rights?level=${block}&max_priority=${maxPriority}`).then(function(info){
        return info
      }).catch(function(){ return false });
    },
    getBlockEndorsingRights: function (block = 'head') {
      return node.query(`/chains/main/blocks/head/helpers/endorsing_rights?level=${block}`).then(function(info){
        return info
      }).catch(function(){ return false });
    },
    getCurrentCycle: function (block = 'head') {
      return node.query(`/chains/main/blocks/${block}/metadata`).then(function(info){
        return info.level.cycle
      }).catch(function(){ return false });
    },
    getLevelsInCurrentCycle: function (block = 'head') {
      return node.query(`/chains/main/blocks/${block}/helpers/levels_in_current_cycle`).then(function(info){
        return info
      }).catch(function(){ return false });
    },
    getHead: function (block = 'head') {
      return node.query(`/chains/main/blocks/${block}`);
    },
    getHeadHash: function (block = 'head') {
      return node.query(`/chains/main/blocks/${block}/hash`);
    },
    call: function (e, d) {
      return node.query(e, d);
    },
    findOperation : function(hash, countFoundBlocks = 1){
      let c = 1;
      return new Promise(function(resolve, reject) {
        var repeater = function(blockPrevNumber){
          rpc.getHead(`head-${blockPrevNumber}`).then(function(h) {
            c++;
            outer:
            for(var i = 3, found = false; i >= 0; i--){
              for(var j = 0; j < h.operations[i].length; j++){
                if (h.operations[i][j].hash == hash){
                  found = true;
                  break outer;
                }
              }
            }
            if (found) resolve(h.hash)
            else {
              if (c > countFoundBlocks) {
                reject("Not found");
              } else {
                repeater(blockPrevNumber + 1);
              }
            }
          });
        }
        repeater(0);
      });
    },
    awaitOperation : function(hash, interval = 30, timeout = 180){
      if (timeout <= 0) throw "Timeout must be more than 0";
      if (interval <= 0) throw "Interval must be more than 0";
      var at = Math.ceil(timeout/interval) + 1, c = 0;;
      return new Promise(function(resolve, reject){
        var repeater = function(){
          rpc.getHead().then(function(h) {
            c++;
            outer:
            for(var i = 3, found = false; i >= 0; i--){
              for(var j = 0; j < h.operations[i].length; j++){
                if (h.operations[i][j].hash == hash){
                  found = true;
                  break outer;
                }
              }
            }
            if (found) resolve(h.hash)
            else {
              if (c >= at) {
                reject("Timeout");
              } else {
                setTimeout(repeater, interval);
              }
            }
          });
        }
        repeater();
      });
    },

    buildOperation: function (from, operation, keys) {
      var counter, opOb;
      var promises = [], requiresReveal=false;

      promises.push(node.query('/chains/main/blocks/head/header'));

      let ops;
      if (Array.isArray(operation)) {
        ops = operation;
      } else {
        ops = [operation];
      }
     
      for(let i = 0; i < ops.length; i++){
        if (['transaction','mine_transaction','origination','delegation'].indexOf(ops[i].kind) >= 0){
          requiresReveal = true;
          promises.push(node.query('/chains/main/blocks/head/context/contracts/' + from + '/counter'));
          promises.push(node.query('/chains/main/blocks/head/context/contracts/' + from + '/manager_key'));
          break;
        }
      }

      return Promise.all(promises).then(function (f) {
        head = f[0];

        if (requiresReveal && f[2] === null){
          ops.unshift({
            kind : "reveal",
            fee : 0,
            gas_limit: utility.mutez(0.010307).toString(),
            public_key : keys.pk,
            source : keys.pkh,
          });
        }
        counter = parseInt(f[1]) + 1;
        
        for(let i = 0; i < ops.length; i++){
          if (['proposals','ballot','transaction','mine_transaction','origination','delegation'].indexOf(ops[i].kind) >= 0){
            if (typeof ops[i].source == 'undefined') ops[i].source = from;
          }
          if (['reveal', 'transaction','mine_transaction','origination','delegation'].indexOf(ops[i].kind) >= 0) {
            if (typeof ops[i].gas_limit == 'undefined') ops[i].gas_limit = "0";
            if (typeof ops[i].storage_limit == 'undefined') ops[i].storage_limit = "0";
            ops[i].counter = (counter++).toString();
            
             ops[i].fee = ops[i].fee.toString();
             ops[i].gas_limit = ops[i].gas_limit.toString();
             ops[i].storage_limit = ops[i].storage_limit.toString();
             ops[i].counter = ops[i].counter.toString();
          }
        }
        opOb = {
          "branch": head.hash,
          "contents": ops,
        }

        return node.query('/chains/'+head.chain_id+'/blocks/'+head.hash+'/helpers/forge/operations', opOb).then((opbytes) => {
          return {
            opbytes,
            opOb
          }
        });
      });
    },
    signOperation: function (opbytes, keys) {
      var sopbytes;
      var signed = crypto.sign(opbytes, keys.sk, watermark.generic);
      sopbytes = signed.sbytes;

      const out = new Buffer(32);
      library.sodium.crypto_generichash(out, utility.hex2buf(sopbytes))

      var oh = utility.b58cencode(out, prefix.o);
      return { sopbytes, signature: signed.edsig };
    },
    validateOperation: function (opOb) {
      return node.query('/chains/main/blocks/head/header').then((head) => {
        return node.query('/chains/'+head.chain_id+'/blocks/'+head.hash+'/helpers/preapply/operations', [opOb]).then((returnedContracts) => {
          var errors = [], opResponse = [];

          if (!Array.isArray(returnedContracts)) throw {error: "RPC Fail", errors:[]};
          for(var i = 0; i < returnedContracts.length; i++){
            for(var j = 0; j < returnedContracts[i].contents.length; j++){
              opResponse.push(returnedContracts[i].contents[j]);
              if (typeof returnedContracts[i].contents[j].metadata.operation_result != 'undefined' && returnedContracts[i].contents[j].metadata.operation_result.status == "failed")
                errors = errors.concat(returnedContracts[i].contents[j].metadata.operation_result.errors);
            }
          } 
          return { opResponse, errors };
        });
      });
    },
    broadcastOperation: function (sopbytes) {
      return node.query('/injection/operation', sopbytes).then(function (f) {
        return {
          hash : f,
        };
      });
    },

    sendOperation: function (from, operation, keys) {
      return rpc.buildOperation(from, operation, keys).then(({ opbytes, opOb }) => {
        var { sopbytes, signature } = rpc.signOperation(opbytes, keys);
        opOb.protocol = "Pt4xzupCszbuxgMSWE2WnReY4aryz1Te3pGN78YEkhjss7C1AMK";
        opOb.signature = signature;

        return rpc.validateOperation(opOb).then(({ errors, opResponse }) => {
          if (errors.length) throw {error: "Operation Failed", errors:errors};
          return rpc.broadcastOperation(sopbytes).then(({ hash }) => {
            return {
              hash,
              opResponse,
            }
          })
        })
      })
    },
    plex_transfer: function (from, keys, to, amount, fee) {
      var operation = {
        "kind": "transaction",
        "fee" : utility.mutez(fee).toString(),
        "gas_limit": utility.mutez(0.010307).toString(),
        "storage_limit": utility.mutez(0.000257).toString(),
        "amount": utility.mutez(amount).toString(),
        "destination": to
      };
      return rpc.sendOperation(from, operation, keys);
    },
    mine_transfer: function (from, keys, to, amount, fee) {
      var operation = {
        "kind": "mine_transaction",
        "fee" : utility.mutez(fee).toString(),
        "gas_limit": utility.mutez(0.010307).toString(),
        "storage_limit": utility.mutez(0.000257).toString(),
        "amount": utility.mutez(amount).toString(),
        "destination": to
      };
      return rpc.sendOperation(from, operation, keys);
    },
    getPricePlexForOneMine: async (total_stake = 0, block = 'head') => {
      const constants = await rpc.getConstants(block);
      if (!constants)
        throw new Error('error load constants');

      const count_plex_per_block = 
        constants.endorsers_per_block * (
          utility.totez(constants.baking_reward_per_endorsement[0]) + 
          utility.totez(constants.endorsement_reward[0])
        );

      // const delegates = await rpc.getAllActiveDelegates()
      // const mine_balances = total_stake || await delegates.reduce(async (acc, delegate) => 
      //   await acc + utility.totez(await rpc.getStakingMineBalance(delegate)), 
      //   0
      // );

      return ((20 / 100) * (total_stake / count_plex_per_block)) / 43200;
    },
    getPriceMineForOnePlex: async (total_stake = 0, block = 'head') => {
      return await rpc.getPricePlexForOneMine(total_stake, block) / 100;
    },
    activate: function (keys, pkh, secret) {
      var operation = {
        "kind": "activate_account",
        "pkh" : pkh,
        "secret": secret,
      };
      return rpc.sendOperation(keys.pkh, operation, keys);
    },
    originate: function (from, keys, amount, code, init, spendable, delegatable, delegate, fee) {
      var _code = utility.ml2mic(code), script = {
        code: _code,
        storage: utility.sexp2mic(init)
      }, operation = {
        "kind": "origination",
        "fee" : fee.toString(),
        "gas_limit": "10000",
        "storage_limit": "10000",
        "managerPubkey": keys.pkh,
        "balance": utility.mutez(amount).toString(),
        "spendable": (typeof spendable != "undefined" ? spendable : false),
        "delegatable": (typeof delegatable != "undefined" ? delegatable : false),
        "delegate": (typeof delegate != "undefined" && delegate ? delegate : keys.pkh),
        "script": script,
      };
      return rpc.sendOperation(from, operation, keys);
    },
    setDelegate(from, keys, delegate, fee) {
      var operation = {
        "kind": "delegation",
        "fee" : utility.mutez(fee).toString(),
        "gas_limit": utility.mutez(0.010307).toString(),
        "delegate": delegate ? delegate : undefined,
      };
      return rpc.sendOperation(from, operation, keys);
    },
    registerDelegate(keys, fee) {
      var operation = {
        "kind": "delegation",
        "fee" : fee.toString(),
        "delegate": keys.pkh,
      };
      return rpc.sendOperation(keys.pkh, operation, keys);
    },
    typecheckCode(code) {
      var _code = utility.ml2mic(code);
      return node.query("/chains/main/blocks/head/helpers/scripts/typecheck_code", {program : _code, gas : "10000"});
    },
    typecheckData(data, type) {
      var check = {
        data: utility.sexp2mic(data),
        type: utility.sexp2mic(type),
        gas:"400000"
      };
      return node.query("/chains/main/blocks/head/helpers/scripts/typecheck_data", check);
    },
    hashData(data, type) {
     var check = {
        data: utility.sexp2mic(data),
        type: utility.sexp2mic(type),
        gas:"400000"
      };
      return node.query("/chains/main/blocks/head/helpers/scripts/hash_data", check);
    },
    runCode(from, code, amount, input, storage, trace) {
      var ep = (trace ? 'trace_code' : 'run_code');
      return node.query("/chains/main/blocks/head/helpers/scripts/" + ep, {
        contract: from,
        script: utility.ml2mic(code),
        amount: utility.mutez(amount).toString(),
        input: utility.sexp2mic(input),
        storage: utility.sexp2mic(storage),
      });
    }
  },
  contract = {
    hash : function(operationHash, ind){
      var ob = utility.b58cdecode(operationHash, prefix.o), tt = [], i=0;
      for(; i<ob.length; i++){
        tt.push(ob[i]);
      }
      tt = tt.concat([
       (ind & 0xff000000) >> 24,
       (ind & 0x00ff0000) >> 16,
       (ind & 0x0000ff00) >> 8,
       (ind & 0x000000ff)
      ]);
      return utility.b58cencode(library.sodium.crypto_generichash(20, new Uint8Array(tt)), prefix.MP);
    },
    originate: function (keys, amount, code, init, spendable, delegatable, delegate, fee) {
      return rpc.originate(keys, amount, code, init, spendable, delegatable, delegate, fee);
    },
    storage: function (contract) {
      return new Promise(function (resolve, reject) {
        mpapi.node.query("/chains/main/blocks/head/context/contracts/" + contract + 
        "/storage").then(function (r) {
          resolve(r);
        }).catch(function (e) {
          reject(e);
        });
      });
    },
    load: function (contract) {
      return mpapi.node.query("/chains/main/blocks/head/context/contracts/" + contract);
    },
    watch: function (cc, timeout, cb) {
      let storage = [];
      const ct = function () {
        contract.storage(cc).then(function (r) {
          if (JSON.stringify(storage) != JSON.stringify(r)) {
            storage = r;
            cb(storage);
          }
        });
      };
      ct();
      return setInterval(ct, timeout * 1000);
    },
    send: function (contract, from, keys, amount, parameter, fee) {
      return mpapi.rpc.sendOperation(from, {
        "kind": "transaction",
        "fee" : fee.toString(),
        "gas_limit": "200",
        "amount": utility.mutez(amount).toString(),
        "destination": contract,
        "parameters": mpapi.utility.sexp2mic(parameter)
      }, keys);
    }
  };

//Legacy commands
utility.ml2mpjson = utility.sexp2mic;
utility.mpjson2arr = utility.mic2arr;
utility.mlraw2json = utility.ml2mic;
utility.mintomp = utility.totez;
utility.mptomin = utility.mutez;
prefix.MP = new Uint8Array([2,90,121]);

//Expose library
const mpapi = {
  library: library,
  prefix: prefix,
  watermark: watermark,
  utility: utility,
  crypto: crypto,
  node: node,
  rpc: rpc,
  contract: contract,
};

module.exports = {
  defaultProvider,
  mpapi: mpapi,
};
