'use strict';

const Joi = require('joi');
const ObjectId = require('mongodb').ObjectId;
const tools = require('../tools');
const roles = require('../roles');
const acl = require('../acl');
const { sessSchema, sessIPSchema, booleanSchema } = require('../schemas');
const { userId, mailboxId } = require('../schemas/request/general-schemas');
const { successRes } = require('../schemas/response/general-schemas');

const granteeId = Joi.string().hex().lowercase().length(24).required().description('Grantee user ID');
const rightsSchema = Joi.string()
    .max(16)
    .regex(/^[lrswipkxteacd]+$/)
    .description('RFC 4314 rights characters granted to the user, lowercase only');

module.exports = (db, server, notifier, loggelf) => {
    loggelf = typeof loggelf === 'function' ? loggelf : () => false;
    const loadMailboxData = async (req, res, result) => {
        let user = new ObjectId(result.value.user);
        let mailbox = new ObjectId(result.value.mailbox);

        let userData;
        try {
            userData = await db.users.collection('users').findOne(
                {
                    _id: user
                },
                {
                    projection: {
                        _id: true
                    }
                }
            );
        } catch (err) {
            res.status(500);
            res.json({
                error: 'MongoDB Error: ' + err.message,
                code: 'InternalDatabaseError'
            });
            return false;
        }
        if (!userData) {
            res.status(404);
            res.json({
                error: 'This user does not exist',
                code: 'UserNotFound'
            });
            return false;
        }

        let mailboxData;
        try {
            mailboxData = await db.database.collection('mailboxes').findOne({
                _id: mailbox,
                user
            });
        } catch (err) {
            res.status(500);
            res.json({
                error: 'MongoDB Error: ' + err.message,
                code: 'InternalDatabaseError'
            });
            return false;
        }
        if (!mailboxData) {
            res.status(404);
            res.json({
                error: 'This mailbox does not exist',
                code: 'NoSuchMailbox'
            });
            return false;
        }

        return mailboxData;
    };

    const loadUserData = async (req, res, result) => {
        let user = new ObjectId(result.value.user);

        let userData;
        try {
            userData = await db.users.collection('users').findOne(
                {
                    _id: user
                },
                {
                    projection: {
                        _id: true
                    }
                }
            );
        } catch (err) {
            res.status(500);
            res.json({
                error: 'MongoDB Error: ' + err.message,
                code: 'InternalDatabaseError'
            });
            return false;
        }
        if (!userData) {
            res.status(404);
            res.json({
                error: 'This user does not exist',
                code: 'UserNotFound'
            });
            return false;
        }

        return userData;
    };

    server.get(
        {
            path: '/users/:user/acl',
            tags: ['ACL'],
            summary: 'List ACL entries of all Mailboxes of a User',
            description: 'Lists every grant the user has given on their mailboxes.',
            name: 'getUserAcl',
            validationObjs: {
                requestBody: {},
                pathParams: {
                    user: userId
                },
                queryParams: {
                    sess: sessSchema,
                    ip: sessIPSchema
                },
                response: {
                    200: {
                        description: 'Success',
                        model: Joi.object({
                            success: successRes,
                            results: Joi.array()
                                .items(
                                    Joi.object({
                                        mailbox: Joi.string().required().description('Mailbox ID'),
                                        path: Joi.string().required().description('Mailbox path'),
                                        user: Joi.string().required().description('Grantee user ID'),
                                        username: Joi.string().required().description('Grantee username'),
                                        rights: Joi.string().required().description('RFC 4314 rights characters'),
                                        subscribed: booleanSchema.required().description('Grantee subscription status for this mailbox'),
                                        created: Joi.date().description('Time the entry was created')
                                    }).$_setFlag('objectName', 'GetUserAclResult')
                                )
                                .required()
                                .description('ACL entries of the mailboxes of this user')
                        }).$_setFlag('objectName', 'GetUserAclResponse')
                    }
                }
            }
        },
        tools.responseWrapper(async (req, res) => {
            res.charSet('utf-8');

            const { pathParams, requestBody, queryParams } = req.route.spec.validationObjs;

            const schema = Joi.object({
                ...pathParams,
                ...requestBody,
                ...queryParams
            });

            const result = schema.validate(req.params, {
                abortEarly: false,
                convert: true
            });

            if (result.error) {
                res.status(400);
                return res.json({
                    error: result.error.message,
                    code: 'InputValidationError',
                    details: tools.validationErrors(result)
                });
            }

            // permissions check
            if (req.user && req.user === result.value.user) {
                req.validate(roles.can(req.role).readOwn('acl'));
            } else {
                req.validate(roles.can(req.role).readAny('acl'));
            }

            let userData = await loadUserData(req, res, result);
            if (!userData) {
                return;
            }

            let grants;
            try {
                grants = await acl.asyncListOwnerGrants(userData._id);
            } catch (err) {
                res.status(500);
                return res.json({
                    error: 'MongoDB Error: ' + err.message,
                    code: 'InternalDatabaseError'
                });
            }

            return res.json({
                success: true,
                results: grants.map(aclData => ({
                    mailbox: aclData.mailbox.toString(),
                    path: aclData.path,
                    user: aclData.user.toString(),
                    username: aclData.username,
                    rights: aclData.rights,
                    subscribed: aclData.subscribed,
                    created: aclData.created
                }))
            });
        })
    );

    server.get(
        {
            path: '/users/:user/acl/shared',
            tags: ['ACL'],
            summary: 'List Mailboxes shared with a User',
            description: 'Lists every mailbox other users have granted to the user, with the rights held and the path in the shared namespace.',
            name: 'getUserSharedMailboxes',
            validationObjs: {
                requestBody: {},
                pathParams: {
                    user: userId
                },
                queryParams: {
                    sess: sessSchema,
                    ip: sessIPSchema
                },
                response: {
                    200: {
                        description: 'Success',
                        model: Joi.object({
                            success: successRes,
                            results: Joi.array()
                                .items(
                                    Joi.object({
                                        mailbox: Joi.string().required().description('Mailbox ID'),
                                        path: Joi.string().required().description('Path of the mailbox in the shared namespace'),
                                        owner: Joi.string().required().description('Owner user ID'),
                                        ownerName: Joi.string().required().description('Owner username'),
                                        rights: Joi.string().required().description('RFC 4314 rights characters held by the user'),
                                        subscribed: booleanSchema.required().description('Subscription status of the user for this mailbox'),
                                        created: Joi.date().description('Time the entry was created')
                                    }).$_setFlag('objectName', 'GetUserSharedMailboxesResult')
                                )
                                .required()
                                .description('Mailboxes shared with this user')
                        }).$_setFlag('objectName', 'GetUserSharedMailboxesResponse')
                    }
                }
            }
        },
        tools.responseWrapper(async (req, res) => {
            res.charSet('utf-8');

            const { pathParams, requestBody, queryParams } = req.route.spec.validationObjs;

            const schema = Joi.object({
                ...pathParams,
                ...requestBody,
                ...queryParams
            });

            const result = schema.validate(req.params, {
                abortEarly: false,
                convert: true
            });

            if (result.error) {
                res.status(400);
                return res.json({
                    error: result.error.message,
                    code: 'InputValidationError',
                    details: tools.validationErrors(result)
                });
            }

            // permissions check
            if (req.user && req.user === result.value.user) {
                req.validate(roles.can(req.role).readOwn('acl'));
            } else {
                req.validate(roles.can(req.role).readAny('acl'));
            }

            let userData = await loadUserData(req, res, result);
            if (!userData) {
                return;
            }

            let entries;
            try {
                entries = await acl.asyncGetSharedEntries(userData._id);
            } catch (err) {
                res.status(500);
                return res.json({
                    error: 'MongoDB Error: ' + err.message,
                    code: 'InternalDatabaseError'
                });
            }

            return res.json({
                success: true,
                results: entries.map(({ aclData, mailboxData, ownerData }) => ({
                    mailbox: mailboxData._id.toString(),
                    path: acl.formatPath(acl.ownerNamespace(ownerData), ownerData.username, mailboxData.path),
                    owner: ownerData._id.toString(),
                    ownerName: ownerData.username,
                    rights: acl.normalizeRights(aclData.rights),
                    subscribed: aclData.subscribed !== false,
                    created: aclData.created
                }))
            });
        })
    );

    server.get(
        {
            path: '/users/:user/mailboxes/:mailbox/acl',
            tags: ['ACL'],
            summary: 'List ACL entries of a Mailbox',
            name: 'getMailboxAcl',
            validationObjs: {
                requestBody: {},
                pathParams: {
                    user: userId,
                    mailbox: mailboxId
                },
                queryParams: {
                    sess: sessSchema,
                    ip: sessIPSchema
                },
                response: {
                    200: {
                        description: 'Success',
                        model: Joi.object({
                            success: successRes,
                            results: Joi.array()
                                .items(
                                    Joi.object({
                                        user: Joi.string().required().description('Grantee user ID'),
                                        username: Joi.string().required().description('Grantee username'),
                                        rights: Joi.string().required().description('RFC 4314 rights characters'),
                                        subscribed: booleanSchema.required().description('Grantee subscription status for this mailbox'),
                                        created: Joi.date().description('Time the entry was created')
                                    }).$_setFlag('objectName', 'GetMailboxAclResult')
                                )
                                .required()
                                .description('ACL entries of this mailbox')
                        }).$_setFlag('objectName', 'GetMailboxAclResponse')
                    }
                }
            }
        },
        tools.responseWrapper(async (req, res) => {
            res.charSet('utf-8');

            const { pathParams, requestBody, queryParams } = req.route.spec.validationObjs;

            const schema = Joi.object({
                ...pathParams,
                ...requestBody,
                ...queryParams
            });

            const result = schema.validate(req.params, {
                abortEarly: false,
                convert: true
            });

            if (result.error) {
                res.status(400);
                return res.json({
                    error: result.error.message,
                    code: 'InputValidationError',
                    details: tools.validationErrors(result)
                });
            }

            // permissions check
            if (req.user && req.user === result.value.user) {
                req.validate(roles.can(req.role).readOwn('acl'));
            } else {
                req.validate(roles.can(req.role).readAny('acl'));
            }

            let mailboxData = await loadMailboxData(req, res, result);
            if (!mailboxData) {
                return;
            }

            let grants;
            try {
                grants = await acl.asyncListGrants(mailboxData._id);
            } catch (err) {
                res.status(500);
                return res.json({
                    error: 'MongoDB Error: ' + err.message,
                    code: 'InternalDatabaseError'
                });
            }

            return res.json({
                success: true,
                results: grants.map(aclData => ({
                    user: aclData.user.toString(),
                    username: aclData.username,
                    rights: aclData.rights,
                    subscribed: aclData.subscribed,
                    created: aclData.created
                }))
            });
        })
    );

    server.put(
        {
            path: '/users/:user/mailboxes/:mailbox/acl',
            tags: ['ACL'],
            summary: 'Set ACL entry for a Mailbox',
            description: 'Creates or updates the rights another user of this server holds for the mailbox. Rights are replaced, not merged.',
            name: 'updateMailboxAcl',
            validationObjs: {
                requestBody: {
                    identifier: Joi.string().max(256).required().description('Username of the user the rights are granted to'),
                    rights: rightsSchema.required()
                },
                pathParams: {
                    user: userId,
                    mailbox: mailboxId
                },
                queryParams: {
                    sess: sessSchema,
                    ip: sessIPSchema
                },
                response: {
                    200: {
                        description: 'Success',
                        model: Joi.object({
                            success: successRes,
                            id: Joi.string().required().description('Grantee user ID')
                        }).$_setFlag('objectName', 'UpdateMailboxAclResponse')
                    }
                }
            }
        },
        tools.responseWrapper(async (req, res) => {
            res.charSet('utf-8');

            const { pathParams, requestBody, queryParams } = req.route.spec.validationObjs;

            const schema = Joi.object({
                ...pathParams,
                ...requestBody,
                ...queryParams
            });

            const result = schema.validate(req.params, {
                abortEarly: false,
                convert: true
            });

            if (result.error) {
                res.status(400);
                return res.json({
                    error: result.error.message,
                    code: 'InputValidationError',
                    details: tools.validationErrors(result)
                });
            }

            // permissions check
            if (req.user && req.user === result.value.user) {
                req.validate(roles.can(req.role).updateOwn('acl'));
            } else {
                req.validate(roles.can(req.role).updateAny('acl'));
            }

            let mailboxData = await loadMailboxData(req, res, result);
            if (!mailboxData) {
                return;
            }

            let granteeData;
            try {
                granteeData = await acl.asyncResolveIdentifier(result.value.identifier, { grantee: true });
            } catch (err) {
                res.status(500);
                return res.json({
                    error: 'MongoDB Error: ' + err.message,
                    code: 'InternalDatabaseError'
                });
            }

            if (!granteeData) {
                res.status(404);
                return res.json({
                    error: 'This identifier does not exist',
                    code: 'UserNotFound'
                });
            }

            if (granteeData._id.toString() === mailboxData.user.toString()) {
                res.status(400);
                return res.json({
                    error: 'Can not modify the rights of the mailbox owner',
                    code: 'InvalidGrantee'
                });
            }

            let sameTenant;
            try {
                sameTenant = await acl.asyncCheckTenantScope(mailboxData.user, granteeData);
            } catch (err) {
                res.status(500);
                return res.json({
                    error: 'MongoDB Error: ' + err.message,
                    code: 'InternalDatabaseError'
                });
            }

            if (!sameTenant) {
                // respond exactly like for an unknown identifier
                res.status(404);
                return res.json({
                    error: 'This identifier does not exist',
                    code: 'UserNotFound'
                });
            }

            let rights;
            try {
                let aclData = await acl.asyncGetGrant(mailboxData._id, granteeData._id);
                let previousRights = acl.normalizeRights((aclData && aclData.rights) || '');

                rights = acl.normalizeRights(result.value.rights);
                await acl.asyncSetGrant(mailboxData, granteeData, rights);

                if (notifier && previousRights.split('').some(right => rights.indexOf(right) < 0)) {
                    // rights were revoked: kick active sessions of the grantee from the mailbox
                    notifier.fire(granteeData._id, {
                        command: 'DROP',
                        mailbox: mailboxData._id
                    });
                }
            } catch (err) {
                if (err.code === 'AclLimitReached') {
                    res.status(400);
                    return res.json({
                        error: err.message,
                        code: err.code
                    });
                }
                res.status(500);
                return res.json({
                    error: 'MongoDB Error: ' + err.message,
                    code: 'InternalDatabaseError'
                });
            }

            loggelf({
                short_message: '[ACLUPDATE] +',
                _mail_action: 'acl_update',
                _owner: mailboxData.user.toString(),
                _mailbox: mailboxData._id.toString(),
                _mailbox_path: mailboxData.path,
                _grantee: granteeData._id.toString(),
                _rights: rights,
                _sess: result.value.sess,
                _ip: result.value.ip,
                _source: 'api'
            });

            return res.json({
                success: true,
                id: granteeData._id.toString()
            });
        })
    );

    server.del(
        {
            path: '/users/:user/mailboxes/:mailbox/acl/:grantee',
            tags: ['ACL'],
            summary: 'Delete ACL entry of a Mailbox',
            name: 'deleteMailboxAcl',
            validationObjs: {
                requestBody: {},
                pathParams: {
                    user: userId,
                    mailbox: mailboxId,
                    grantee: granteeId
                },
                queryParams: {
                    sess: sessSchema,
                    ip: sessIPSchema
                },
                response: {
                    200: {
                        description: 'Success',
                        model: Joi.object({
                            success: successRes
                        }).$_setFlag('objectName', 'DeleteMailboxAclResponse')
                    }
                }
            }
        },
        tools.responseWrapper(async (req, res) => {
            res.charSet('utf-8');

            const { pathParams, requestBody, queryParams } = req.route.spec.validationObjs;

            const schema = Joi.object({
                ...pathParams,
                ...requestBody,
                ...queryParams
            });

            const result = schema.validate(req.params, {
                abortEarly: false,
                convert: true
            });

            if (result.error) {
                res.status(400);
                return res.json({
                    error: result.error.message,
                    code: 'InputValidationError',
                    details: tools.validationErrors(result)
                });
            }

            // permissions check
            if (req.user && req.user === result.value.user) {
                req.validate(roles.can(req.role).deleteOwn('acl'));
            } else {
                req.validate(roles.can(req.role).deleteAny('acl'));
            }

            let mailboxData = await loadMailboxData(req, res, result);
            if (!mailboxData) {
                return;
            }

            let grantee = new ObjectId(result.value.grantee);

            let removed;
            try {
                removed = await acl.asyncDeleteGrant(mailboxData._id, grantee);
            } catch (err) {
                res.status(500);
                return res.json({
                    error: 'MongoDB Error: ' + err.message,
                    code: 'InternalDatabaseError'
                });
            }

            if (removed.removed) {
                if (notifier) {
                    // kick active sessions of the grantee from the mailbox
                    notifier.fire(grantee, {
                        command: 'DROP',
                        mailbox: mailboxData._id
                    });
                }

                loggelf({
                    short_message: '[ACLUPDATE] -',
                    _mail_action: 'acl_delete',
                    _owner: mailboxData.user.toString(),
                    _mailbox: mailboxData._id.toString(),
                    _mailbox_path: mailboxData.path,
                    _grantee: grantee.toString(),
                    _sess: result.value.sess,
                    _ip: result.value.ip,
                    _source: 'api'
                });
            }

            return res.json({
                success: true
            });
        })
    );
};
