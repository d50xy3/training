var crypto = require("crypto");

var block =
{
    "bits": "18121472", 
    "chainwork": "0000000000000000000000000000000000000000000aeb55a866a589db70f122", 
    "confirmations": 8483, 
    "difficulty": 60813224039.440346, 
    "hash": "000000000000000006a8961c438339d28db630515ec7da0bfc62327f3dc6f314", 
    "height": 378066, 
    "isMainChain": true, 
    "merkleroot": "d3f0e717a577ae8139c7e3261da26f3dc66a618bd4661e03b9860cb738b55806", 
    "nextblockhash": "00000000000000000ef9af22be9e30034d259e9189319350b0bcfd5df42d6bd1", 
    "nonce": 1438955897, 
    "poolInfo": {
        "poolName": "AntMiner", 
        "url": "https://bitmaintech.com/"
    }, 
    "previousblockhash": "00000000000000000a5093e24e1f43c509e2cd51dd3ec38c739a92de83665b5a", 
    "reward": 25, 
    "size": 3182, 
    "time": 1444349800, 
    "tx": [
        "aa80a8b04a45974d5dbe16ed5067c9b019e14249522723ce5e376b9c7c9d106e", 
        "1d93e173294fe0bef5e663b05fdec2684b38d72cae97943a644d258b863a8386", 
        "97509a6e396b19cc0aa3a8774faa858c38ebd8093a1049121d08fa9f49251001", 
        "534bdd8484c6c336ee93f190074e305b02dfcd6c07df6ee758b093f4a2d944f3", 
        "5d7813034b8a1c39d9fe568d4ba702ef45408cf4ec1d1e8ed93155d5a2b6590e", 
        "26b61f5d962023437afe0f17a3938ba18e0e1317d7146039b0d0da79af4fc22e", 
        "36901af8e968e159ffd45f6895f479f1fafc5d34bae7c943ebc93eb1a0e23c70", 
        "3a998ff11675977df35697f3060a257ede03211e22ab1f68b2579bcdd349337d", 
        "a44ca0919b65e8ef19ee1ef3657578a8d929245e421184ca4704d571bddd640a"
    ], 
    "version": 3
}

console.log(verifyBlock(block));

function verifyBlock(block) {
	var version = intToHex(block.version, 4);
	var previous_block_hash;

	if (block.hasOwnProperty("previousblockhash"))
		previous_block_hash = swapEndianness(block.previousblockhash)
	else
	 	previous_block_hash = intToHex(0, 32);

	var hash_merkle_root = swapEndianness(getMerkelRoot(block.tx));
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

function getMerkelRoot(transactions) {
	var hash1;
	var hash2;
	var buffers;
	var result = [];

	for (var i = 0; i < transactions.length; i += 2) {
		hash1 = crypto.createHash("sha256");
		hash2 = crypto.createHash("sha256");
		buffers = [];
		buffers.push(new Buffer(swapEndianness(transactions[i]), 'hex'));

		if (i == transactions.length - 1)
			buffers.push(new Buffer(swapEndianness(transactions[i]), 'hex'));
		else
			buffers.push(new Buffer(swapEndianness(transactions[i + 1]), 'hex'));

		hash1.update(Buffer.concat(buffers));
		hash2.update(hash1.digest());

		result.push(swapEndianness(hash2.digest("hex")));
	}

	if (result.length > 1)
		return getMerkelRoot(result);
	else 
		return result[0];
}

function intToHex(int, size) {
	var buffer = new Buffer(size);
	buffer.fill(0);
	buffer.writeUInt32LE(int);

	return buffer.toString('hex');
}

function swapEndianness(input) {
	var output = '';

	for (var i = input.length - 1; i > 0; i -= 2) {
		output += input[i - 1] + input[i];
	}

	return output;
}