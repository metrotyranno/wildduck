'use strict';

const acl = require('../acl');
const { resolveMailbox } = require('../mailbox-resolver');

// DELETE "path/to/mailbox"
module.exports = (server, mailboxHandler) => (path, session, callback) => {
    server.logger.debug(
        {
            tnx: 'delete',
            cid: session.id
        },
        '[%s] DELETE "%s"',
        session.id,
        path
    );

    resolveMailbox(server, session, path, { requireRights: acl.ACL_RIGHTS.DELETE_MAILBOX }, (err, resolved) => {
        if (err) {
            return callback(err);
        }

        let mailbox = resolved.mailboxData;
        if (!mailbox) {
            return callback(null, 'NONEXISTENT');
        }

        if (resolved.denied) {
            return callback(null, 'NOPERM');
        }

        mailboxHandler.del(resolved.owner, mailbox._id, callback);
    });
};
