'use strict';

const db = require('../db');
const consts = require('../consts');
const acl = require('../acl');

module.exports = server => (quotaRoot, session, callback) => {
    server.logger.debug(
        {
            tnx: 'quota',
            cid: session.id
        },
        '[%s] Requested quota info for "%s"',
        session.id,
        quotaRoot
    );

    let parsed = acl.isEnabled(server) ? acl.parseQuotaRoot(quotaRoot) : { shared: false, root: quotaRoot };

    let resolveUser = next => {
        if (!parsed.shared) {
            if (quotaRoot !== '') {
                return callback(null, 'NONEXISTENT');
            }
            return next(null, session.user.id);
        }

        // quota root of another account: only visible if that account shares at least one mailbox
        acl.resolveIdentifier(parsed.identifier, (err, ownerData) => {
            if (err) {
                return callback(err);
            }

            if (!ownerData || acl.ownerNamespace(ownerData) !== parsed.namespace) {
                // unknown owner, or the quota root names the wrong namespace for the account kind
                return callback(null, 'NONEXISTENT');
            }

            db.database.collection('mailboxacls').findOne(
                {
                    user: session.user.id,
                    owner: ownerData._id
                },
                {
                    projection: {
                        rights: true
                    },
                    maxTimeMS: consts.DB_MAX_TIME_MAILBOXES
                },
                (err, aclData) => {
                    if (err) {
                        return callback(err);
                    }

                    let rights = aclData && acl.normalizeRights(aclData.rights);
                    if (!aclData || !(acl.hasRight(rights, acl.ACL_RIGHTS.LOOKUP) || acl.hasRight(rights, acl.ACL_RIGHTS.READ))) {
                        // do not disclose the quota of unrelated users
                        return callback(null, 'NONEXISTENT');
                    }

                    acl.checkTenantScope(ownerData._id, session.user.id, (err, sameTenant) => {
                        if (err) {
                            return callback(err);
                        }

                        if (!sameTenant) {
                            // grants that cross the tenant scope behave as if they do not exist
                            return callback(null, 'NONEXISTENT');
                        }

                        next(null, ownerData._id);
                    });
                }
            );
        });
    };

    resolveUser((err, userId) => {
        if (err) {
            return callback(err);
        }

        db.users.collection('users').findOne(
            {
                _id: userId
            },
            {
                maxTimeMS: consts.DB_MAX_TIME_USERS
            },
            (err, user) => {
                if (err) {
                    return callback(err);
                }
                if (!user) {
                    return callback(new Error('User data not found'));
                }

                let getQuota = next => {
                    if (user.quota) {
                        return next(null, user.quota);
                    }

                    if (!server.options.settingsHandler) {
                        return next(null, 0);
                    }

                    server.options.settingsHandler
                        .get('const:max:storage')
                        .then(maxStorage => next(null, maxStorage))
                        .catch(err => next(err));
                };

                getQuota((err, maxStorage) => {
                    if (err) {
                        return callback(err);
                    }

                    callback(null, {
                        root: quotaRoot,
                        quota: user.quota || maxStorage || 0,
                        storageUsed: Math.max(user.storageUsed || 0, 0)
                    });
                });
            }
        );
    });
};
