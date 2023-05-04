const bigInt = require("big-integer");
const paillier = require("paillier-js")
const crypto = require('crypto');

/// The proof allows a prover to prove that a ciphertext is an encryption of zero.
// https://github.com/ZenGo-X/zk-paillier/blob/master/src/zkproofs/zero_enc_proof.rs
//The code is based on link above

const {publicKey} = paillier.generateRandomKeys(128);

const encryptWithCustomRandomness = ({n, g}, message, r) => {
    const _n2 = n.pow(2);
    return g.modPow(bigInt(message), _n2).multiply(r.modPow(n, _n2)).mod(_n2)
}

function createRandomness(n) {
    let random = require('crypto').randomBytes(256);
    let num = BigInt('0x' + random.toString('hex'));
    return bigInt(num % n.value);
}

function prover(randomnessOfInput, ciphertextOfInput) {
    const r_prime = createRandomness(publicKey.n)
    let a = encryptWithCustomRandomness(publicKey, bigInt(0), r_prime);

    const hash = crypto.createHash('sha256');
    hash.update(publicKey.n.toString());
    hash.update(ciphertextOfInput.toString());
    hash.update(a.toString());
    const e = hash.digest('hex');
    const bigIntValueOfE = BigInt('0x' + e);

    const r_e = randomnessOfInput.modPow(bigIntValueOfE, publicKey._n2);
    const z = r_prime.multiply(r_e).mod(publicKey._n2)

    return {z, a}
}

function verify(proof, ciphertextOfInput) {
    const hash = crypto.createHash('sha256');
    hash.update(publicKey.n.toString());
    hash.update(ciphertextOfInput.toString());
    hash.update(proof.a.toString());
    const e = BigInt('0x' + hash.digest('hex'));

    let c_z = encryptWithCustomRandomness(publicKey, 0, proof.z);
    let c_e = publicKey.multiply(ciphertextOfInput, e);

    let c_z_test = publicKey.addition(c_e, proof.a);

    return c_z.value == c_z_test.value;
}


function testOne() { // Not Valid
    const randomnessOfInput1 = createRandomness(publicKey.n)
    const randomnessOfInput2 = createRandomness(publicKey.n)
    const randomnessOfInput3 = createRandomness(publicKey.n)
    const randomnessOfInput4 = createRandomness(publicKey.n)
    const arrColumnOne = encryptWithCustomRandomness(publicKey, 0, randomnessOfInput1);
    const arrColumnTwo = encryptWithCustomRandomness(publicKey, 0, randomnessOfInput2);
    const arrColumnThree = encryptWithCustomRandomness(publicKey, 1, randomnessOfInput3);
    const ciphertextSum = publicKey.addition(arrColumnOne, arrColumnTwo, arrColumnThree); // sum of votes
    const validMessage = encryptWithCustomRandomness(publicKey, 1,randomnessOfInput4); //valid message
    const inverseOfValidMessage = validMessage.modInv(publicKey._n2);
    const ciphertextOfInput = publicKey.addition(ciphertextSum, inverseOfValidMessage).mod(publicKey._n2);
    const multiplicationOfRandoms = randomnessOfInput1.multiply(randomnessOfInput2).multiply(randomnessOfInput3).multiply(randomnessOfInput4)
    let proof = prover(multiplicationOfRandoms, ciphertextOfInput);
    let verified_result = verify(proof, ciphertextOfInput);
    console.log(verified_result)
}

testOne()

function testTwo() { //VALID
    let result = true;
    for (let i = 0; i < 256; i++) {
        const randomnessOfInput = createRandomness(publicKey.n)
        const ciphertextOfInput = encryptWithCustomRandomness(publicKey, 0, randomnessOfInput);
        let proof = prover(randomnessOfInput, ciphertextOfInput);
        let verified_result = verify(proof, ciphertextOfInput);
        if (verified_result === false) {
            result = false;
            break;
        }
    }
    console.log(result)
}
testTwo()

function testThree() { // NOT VALID
    const randomnessOfInput = createRandomness(publicKey.n)
    const ciphertextOfInput = encryptWithCustomRandomness(publicKey, 1, randomnessOfInput);
    let proof = prover(randomnessOfInput, ciphertextOfInput);
    let verified_result = verify(proof, ciphertextOfInput);
    console.log(verified_result)
}

testThree()


function testFour() {
    const randomnessOfInput = createRandomness(publicKey.n)
    const arrColumnOne = encryptWithCustomRandomness(publicKey, 0, createRandomness(publicKey.n));
    const arrColumnTwo = encryptWithCustomRandomness(publicKey, 0, createRandomness(publicKey.n));
    const arrColumnThree = encryptWithCustomRandomness(publicKey, 1, createRandomness(publicKey.n));
    const ciphertextSum = publicKey.addition(arrColumnOne, arrColumnTwo, arrColumnThree);// sum of votes
    const validMessage = encryptWithCustomRandomness(publicKey, 1, createRandomness(publicKey.n)); //valid message
    const inverseOfValidMessage = validMessage.modInv(publicKey._n2);
    const substracted_vote = publicKey.addition(ciphertextSum, inverseOfValidMessage);
    const ciphertextOfInput = publicKey.addition(substracted_vote, encryptWithCustomRandomness(publicKey,0 , randomnessOfInput))
    let proof = prover(randomnessOfInput, ciphertextOfInput);
    let verified_result = verify(proof, ciphertextOfInput);
    console.log(verified_result)
}
testFour()

