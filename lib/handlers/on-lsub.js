'use strict';

const db = require('../db');
const consts = require('../consts');
const acl = require('../acl');

// LSUB "" "*"
// Returns all subscribed folders, query is informational
// folders is either an Array or a Map
module.exports = server => (query, session, callback) => {
    server.logger.debug(
        {
            tnx: 'lsub',
            cid: session.id
        },
        '[%s] LSUB for "%s"',
        session.id,
        query
    );
    db.database
        .collection('mailboxes')
        .find({
            user: session.user.id,
            subscribed: true,
            hidden: { $ne: true }
        })
        .maxTimeMS(consts.DB_MAX_TIME_MAILBOXES)
        .toArray((err, mailboxes) => {
            if (err) {
                return callback(err);
            }

            if (!acl.isEnabled(server)) {
                return callback(null, mailboxes);
            }

            acl.getSharedMailboxes(session.user.id, { subscribedOnly: true }, (err, shared) => {
                if (err) {
                    return callback(err);
                }

                callback(null, mailboxes.concat(shared));
            });
        });
};
