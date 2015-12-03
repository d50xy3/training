var block =
{
    "bits": "180f1e76", 
    "chainwork": "0000000000000000000000000000000000000000000cdacc6b62d1ff727d1d0a", 
    "confirmations": 9, 
    "difficulty": 72722780642.54718, 
    "hash": "00000000000000000b8c4832b7c02b5146aabf75aa05bd42a84a0055984cce13", 
    "height": 386520, 
    "isMainChain": true, 
    "merkleroot": "3c155d4bf540e459e1717bd8ba0b3577d9a8bf73c12ba2d1a2068041469a60c0", 
    "nextblockhash": "00000000000000000626e82d3fe91eff6850548cb84dd11c46e0ac649a7d9cbd", 
    "nonce": 2653421028, 
    "poolInfo": {
        "poolName": "AntMiner", 
        "url": "https://bitmaintech.com/"
    }, 
    "previousblockhash": "000000000000000008813150384e7ffa4293dc501826496bd7b30c3bfffbce1a", 
    "reward": 25, 
    "size": 208, 
    "time": 1449142747, 
    "tx": [
        "3c155d4bf540e459e1717bd8ba0b3577d9a8bf73c12ba2d1a2068041469a60c0"
    ], 
    "version": 3
}

console.log(verifyBlock(block));

function verifyBlock(block) {
	var crypto = require("crypto");

	var version = intToHex(block.version, 4);
	var previous_block_hash;

	if (block.hasOwnProperty("previousblockhash"))
		previous_block_hash = swapEndianness(block.previousblockhash)
	else
	 	previous_block_hash = intToHex(0, 32);

	var hash_merkle_root = swapEndianness(block.merkleroot);
	var time = intToHex(block.time, 4);
	var bits = swapEndianness(block.bits);
	var nonce = intToHex(block.nonce, 4);
	var block_header = version + previous_block_hash + hash_merkle_root + time + bits + nonce;
	var hash1 = crypto.createHash("sha256");
	var hash2 = crypto.createHash("sha256");

	hash1.update(new Buffer(block_header, 'hex'));
	hash2.update(hash1.digest());

	return swapEndianness(hash2.digest("hex")) === block.hash;
}

function intToHex(int, size) {
	var buffer = new Buffer(size);
	buffer.fill(0);
	buffer.writeUInt32LE(int);

	return buffer.toString('hex');
}

function swapEndianness(input) {
	var output = '';

	for (i = input.length - 1; i > 0; i -= 2) {
		output += input[i - 1] + input[i];
	}

	return output;
}