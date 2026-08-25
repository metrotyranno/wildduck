'use strict';

const { resolveMailbox } = require('../mailbox-resolver');

// RENAME "path/to/mailbox" "new/path"
// NB! RENAME affects child and hierarchy mailboxes as well, this example does not do this
module.exports = (server, mailboxHandler) => (path, newname, session, callback) => {
    server.logger.debug(
        {
            tnx: 'rename',
            cid: session.id
        },
        '[%s] RENAME "%s" to "%s"',
        session.id,
        path,
        newname
    );

    resolveMailbox(server, session, path, (err, resolved) => {
        if (err) {
            return callback(err);
        }

        let mailbox = resolved.mailboxData;
        if (!mailbox) {
            return callback(null, 'NONEXISTENT');
        }

        mailboxHandler.rename(resolved.owner, mailbox._id, newname, false, callback);
    });
};
