var genesis_block =
{
	"hash":"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
	"confirmations":386396,
	"size":285,
	"height":0,
	"version":1,
	"merkleroot":"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
	"tx":["4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"],
	"time":1231006505,
	"nonce":2083236893,
	"bits":"1d00ffff",
	"difficulty":1,
	"chainwork":"0000000000000000000000000000000000000000000000000000000100010001",
	"nextblockhash":"00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
	"isMainChain":true
}

console.log(verifyBlock(genesis_block));

function verifyBlock(block) {
	var crypto = require("crypto");

	var version = intToHex(block.version, 4);
	var hash_prev_block = intToHex(0, 32);
	var hash_merkle_root = swapEndianness(block.merkleroot);
	var time = intToHex(block.time, 4);
	var bits = swapEndianness(block.bits);
	var nonce = intToHex(block.nonce, 4);
	var block_header = version + hash_prev_block + hash_merkle_root + time + bits + nonce;
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