'use strict';

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

    resolveMailbox(server, session, path, (err, resolved) => {
        if (err) {
            return callback(err);
        }

        let mailbox = resolved.mailboxData;
        if (!mailbox) {
            return callback(null, 'NONEXISTENT');
        }

        if (resolved.shared) {
            // deleting mailboxes of other users is not supported
            return callback(null, 'CANNOT');
        }

        mailboxHandler.del(resolved.owner, mailbox._id, callback);
    });
};
