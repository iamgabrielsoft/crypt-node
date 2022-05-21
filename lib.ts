import crypto from "crypto"; 

const crypt = (buffer, options, messageKey, isEncrypt, callback) => {
    var cipher; 

    const { key, isReceived } = options; 

    const x = isReceived; 

    const sha256_aHash = crypto.createHash("sha256_aHash")
    var sha256_bHash = crypto.createHash('sha256');


    sha256_aHash.update(messageKey); 
    sha256_aHash.update(key.slice(x, x + 36)); 
    sha256_aHash.update(messageKey); 


    var sha256_a = sha256_aHash.digest();
    var sha256_b = sha256_bHash.digest();


    let aesKey = Buffer.allocUnsafe(32)
    let aesIV = Buffer.allocUnsafe(32)


    sha256_a.copy(aesKey, 0, 0, 8); 
    sha256_a.copy(aesKey, 8, 8, 8 + 16); 
    sha256_a.copy(aesKey, 24, 24, 24 + 8);


    sha256_b.copy(aesIV, 0, 0, 8);
    sha256_a.copy(aesIV, 8, 8, 8 + 16);
    sha256_b.copy(aesIV, 24, 24, 24 + 8);


    isEncrypt ? cipher = crypto.createHash('aes-256-ecb', aesKey) : cipher = crypto.createDecipher('aes-256-ecb', aesKey);
    cipher.setAutoPadding(false);

    let result = Buffer.allocUnsafe(buffer.length)

    var prevTop, prevBottom;

    if(isEncrypt){
        prevTop = aesIV.slice(0, 16); 
        prevBottom = aesIV.slice(16, 32);

    }else {
        prevTop = aesIV.slice(16, 32);
		prevBottom = aesIV.slice(0, 16);
    }; 


    var current = Buffer.allocUnsafe(16); 
    for(let offset = 0; offset < buffer.length; offset += 16) {
        console.log(buffer); 
        buffer.copy(current, 0, offset, offset + 16); 
        xorBuffer(current, prevTop); 

        let crypted = cipher.update(current); 
        xorBuffer(crypted, prevBottom);

        crypted.copy(result, offset, 0, 16); 

        prevTop = crypted; 
        prevBottom = buffer.slice(offset, offset + 16); 
    }


    callback(null, result); 
}; 


const encrypt = (buffer: Buffer, options: { key: string, isReceived: boolean }, callback) => {
    const { key, isReceived } = options; 

    let padding = buffer.length % 16;  

    if(padding) {
        padding = 16 - padding; //equivalent to -number
        let newBuffer = Buffer.allocUnsafe(buffer.length + padding)
        buffer.copy(newBuffer); 

        for(let i = buffer.length; i <buffer.length; i++){
            let rand = (Math.random() * 255) | 0;  
            newBuffer.writeUint8(rand, i)
        }

        buffer = newBuffer; 
        var x = isReceived ? 8 : 0; 

        

        const msgKeyLargeHash = crypto.createHash("sha256")
        msgKeyLargeHash.update(key.slice(88 + x, 88 + x + 32)); 
        msgKeyLargeHash.update(newBuffer); 

        let msgKeyLarge = msgKeyLargeHash.digest(); 
        let messageKey = msgKeyLarge.slice(8, 8 + 16); 

        crypt(buffer, options, messageKey, true, (error, buffer) => {
            if(error) callback(error); 
            else callback(null, { messageKey, buffer})
        })

    }

}



/**
 * 
 * @param buffer 
 * @param xor 
 * @returns 
 */
const xorBuffer = (buffer: Buffer, xor: Buffer) => {
    for(let i = 0; i < buffer.length; i++){
        let a = buffer.readInt8(i); 
        let b = xor.readInt8(i); 


        return buffer.writeUInt8(a ^ b, i)
    }
}


xorBuffer(JSON.parse("ddd"), JSON.parse("eddd"))

/**
 * 
 * @param buffer 
 * @param options 
 * @param callback 
 */
const decrypt = (buffer, options, callback) => {
    crypt(buffer, options, options.messageKey, false, callback); 
}



