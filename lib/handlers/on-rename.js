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

        if (!resolved.shared) {
            if (acl.isEnabled(server) && acl.parsePath(newname).shared) {
                // renaming mailboxes into other accounts is not supported
                return callback(null, 'CANNOT');
            }

            return mailboxHandler.rename(resolved.owner, mailbox._id, newname, false, callback);
        }

        // renaming inside a shared hierarchy: the destination must stay in the same
        // account and its parent must exist with the create right
        let parsedTarget = acl.parsePath(newname);
        if (!parsedTarget.shared || !parsedTarget.identifier || !parsedTarget.path) {
            return callback(null, 'CANNOT');
        }

        let parentParts = parsedTarget.path.split('/');
        parentParts.pop();

        if (!parentParts.length) {
            // renaming to a top level mailbox of another user is not supported
            return callback(null, 'CANNOT');
        }

        let parentPath = acl.formatPath(parsedTarget.identifier, parentParts.join('/'));

        resolveMailbox(server, session, parentPath, { requireRights: acl.ACL_RIGHTS.CREATE }, (err, resolvedParent) => {
            if (err) {
                return callback(err);
            }

            if (!resolvedParent.mailboxData) {
                return callback(null, 'NONEXISTENT');
            }

            if (resolvedParent.denied) {
                return callback(null, 'NOPERM');
            }

            if (!resolvedParent.owner.equals(resolved.owner)) {
                // source and destination must belong to the same user
                return callback(null, 'CANNOT');
            }

            mailboxHandler.rename(resolved.owner, mailbox._id, parsedTarget.path, false, callback);
        });
    });
};
