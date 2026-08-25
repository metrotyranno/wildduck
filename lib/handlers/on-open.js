'use strict';

const db = require('../db');
const consts = require('../consts');
const { resolveMailbox } = require('../mailbox-resolver');

// SELECT/EXAMINE
module.exports = server => (path, session, callback) => {
    server.logger.debug(
        {
            tnx: 'open',
            cid: session.id
        },
        '[%s] Opening "%s"',
        session.id,
        path
    );
    resolveMailbox(server, session, path, (err, resolved) => {
        if (err) {
            return callback(err);
        }

        let mailbox = resolved.mailboxData;
        if (!mailbox) {
            return callback(null, 'NONEXISTENT');
        }

        if (mailbox.hidden) {
            return callback(null, 'CANNOT');
        }

        db.database
            .collection('messages')
            .find({
                mailbox: mailbox._id
            })
            .project({
                uid: true,
                _id: false
            })
            .sort({ uid: 1 })
            .maxTimeMS(consts.DB_MAX_TIME_MESSAGES)
            .toArray((err, messages) => {
                if (err) {
                    return callback(err);
                }
                // sort and ensure unique UIDs
                mailbox.uidList = Array.from(new Set(messages.map(message => message.uid)));
                callback(null, mailbox);
            });
    });
};
