'use strict';

const acl = require('../acl');
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

        if (resolved.shared || (acl.isEnabled(server) && acl.parsePath(newname).shared)) {
            // renaming mailboxes of other users is not supported
            return callback(null, 'CANNOT');
        }

        mailboxHandler.rename(resolved.owner, mailbox._id, newname, false, callback);
    });
};
