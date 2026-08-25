'use strict';

const db = require('../db');
const consts = require('../consts');
const acl = require('../acl');
const { resolveMailbox } = require('../mailbox-resolver');

// SUBSCRIBE "path/to/mailbox"
module.exports = server => (path, session, callback) => {
    server.logger.debug(
        {
            tnx: 'subscribe',
            cid: session.id
        },
        '[%s] SUBSCRIBE to "%s"',
        session.id,
        path
    );

    if (acl.isEnabled(server) && acl.parsePath(path).shared) {
        // subscriptions of shared mailboxes are personal to the grantee and live on the ACL entry
        return resolveMailbox(server, session, path, { requireRights: acl.ACL_RIGHTS.LOOKUP }, (err, resolved) => {
            if (err) {
                return callback(err);
            }

            if (!resolved.mailboxData) {
                return callback(null, 'NONEXISTENT');
            }

            if (resolved.denied) {
                return callback(null, 'NOPERM');
            }

            db.database.collection('mailboxacls').updateOne(
                {
                    mailbox: resolved.mailboxData._id,
                    user: session.user.id
                },
                {
                    $set: {
                        subscribed: true
                    }
                },
                {
                    maxTimeMS: consts.DB_MAX_TIME_MAILBOXES
                },
                err => {
                    if (err) {
                        return callback(err);
                    }
                    callback(null, true);
                }
            );
        });
    }

    db.database.collection('mailboxes').findOneAndUpdate(
        {
            user: session.user.id,
            path
        },
        {
            $set: {
                subscribed: true
            }
        },
        {
            maxTimeMS: consts.DB_MAX_TIME_MAILBOXES
        },
        (err, item) => {
            if (err) {
                return callback(err);
            }

            if (!item || !item.value) {
                // was not able to acquire a lock
                return callback(null, 'NONEXISTENT');
            }

            callback(null, true);
        }
    );
};
