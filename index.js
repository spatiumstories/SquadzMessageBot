const AWS = require('aws-sdk');
const deso = require('./deso');


async function sendMessage(body) {
    let extra_data = {
        "community_id": body['community_id'],
        "channel_id": body['channel_id'],
        "message_id": body['message_id'],
        "message_type": body["message_type"],
        "images": body["images"],
        "timestamp": body["timestamp"],
        "reply_id": body["reply_id"],
        "replies": body["replies"],
    }
    let response = await deso.sendMessage(extra_data, body['message'], body['sender_public_key']);
    let returnMe = {
        ...extra_data,
        'message': body['message'],
        'sender': body['sender_public_key'],
        'TxnHashHex': response['TxnHashHex']
    };
    return returnMe;
}


exports.handler = async (event, context) => {
    let body;
    let statusCode = '200';
    const headers = {
        'Content-Type': 'application/json',
    };

    try {
        switch (event.httpMethod) {
            case 'GET':
                body = await deso.getMessages(event.body);
                break;
            case 'POST':
                body = await sendMessage(JSON.parse(event.body));
                break;
            default:
                throw new Error(`Unsupported method "${event.httpMethod}"`);
        }
    } catch (err) {
        statusCode = '400';
        body = err.message;
    } finally {
        body = JSON.stringify(body);
    }

    return {
        statusCode,
        body,
        headers,
    };
};
