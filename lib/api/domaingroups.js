'use strict';

const Joi = require('joi');
const tools = require('../tools');
const roles = require('../roles');
const { sessSchema, sessIPSchema } = require('../schemas');
const { successRes } = require('../schemas/response/general-schemas');

const domainSchema = Joi.string().max(255).required().description('Domain name');
const groupSchema = Joi.string()
    .trim()
    .max(128)
    .required()
    .description('Name of the domain group. Users of domains in the same group may share mailboxes with each other');

module.exports = (db, server) => {
    server.get(
        {
            path: '/domaingroups',
            tags: ['DomainGroups'],
            summary: 'List Domain Group entries',
            name: 'getDomainGroups',
            validationObjs: {
                requestBody: {},
                pathParams: {},
                queryParams: {
                    group: Joi.string().trim().empty('').max(128).description('Only list domains of this group'),
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
                                        domain: Joi.string().required().description('Domain name'),
                                        group: Joi.string().required().description('Name of the domain group')
                                    }).$_setFlag('objectName', 'GetDomainGroupsResult')
                                )
                                .required()
                                .description('Domain Group entries')
                        }).$_setFlag('objectName', 'GetDomainGroupsResponse')
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
            req.validate(roles.can(req.role).readAny('domaingroups'));

            let filter = {};
            if (result.value.group) {
                filter.group = result.value.group;
            }

            let entries;
            try {
                entries = await db.users.collection('domaingroups').find(filter).sort({ group: 1, domain: 1 }).toArray();
            } catch (err) {
                res.status(500);
                return res.json({
                    error: 'MongoDB Error: ' + err.message,
                    code: 'InternalDatabaseError'
                });
            }

            return res.json({
                success: true,
                results: entries.map(entryData => ({
                    domain: entryData.domain,
                    group: entryData.group
                }))
            });
        })
    );

    server.post(
        {
            path: '/domaingroups',
            tags: ['DomainGroups'],
            summary: 'Add a Domain to a Domain Group',
            description: 'Users of domains in the same group may share mailboxes with each other. A domain can belong to one group only.',
            name: 'createDomainGroup',
            validationObjs: {
                requestBody: {
                    domain: domainSchema,
                    group: groupSchema
                },
                pathParams: {},
                queryParams: {
                    sess: sessSchema,
                    ip: sessIPSchema
                },
                response: {
                    200: {
                        description: 'Success',
                        model: Joi.object({
                            success: successRes
                        }).$_setFlag('objectName', 'CreateDomainGroupResponse')
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
            req.validate(roles.can(req.role).createAny('domaingroups'));

            let domain = tools.normalizeDomain(result.value.domain);
            let group = result.value.group;

            let existing;
            try {
                existing = await db.users.collection('domaingroups').findOne({ domain });
            } catch (err) {
                res.status(500);
                return res.json({
                    error: 'MongoDB Error: ' + err.message,
                    code: 'InternalDatabaseError'
                });
            }

            if (existing) {
                if (existing.group === group) {
                    return res.json({
                        success: true
                    });
                }
                res.status(400);
                return res.json({
                    error: 'This domain already belongs to another group',
                    code: 'DomainAlreadyGrouped'
                });
            }

            try {
                await db.users.collection('domaingroups').insertOne({
                    domain,
                    group,
                    created: new Date()
                });
            } catch (err) {
                if (err.code === 11000) {
                    res.status(400);
                    return res.json({
                        error: 'This domain already belongs to another group',
                        code: 'DomainAlreadyGrouped'
                    });
                }
                res.status(500);
                return res.json({
                    error: 'MongoDB Error: ' + err.message,
                    code: 'InternalDatabaseError'
                });
            }

            return res.json({
                success: true
            });
        })
    );

    server.del(
        {
            path: '/domaingroups/:domain',
            tags: ['DomainGroups'],
            summary: 'Remove a Domain from its Domain Group',
            name: 'deleteDomainGroup',
            validationObjs: {
                requestBody: {},
                pathParams: {
                    domain: domainSchema
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
                        }).$_setFlag('objectName', 'DeleteDomainGroupResponse')
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
            req.validate(roles.can(req.role).deleteAny('domaingroups'));

            try {
                await db.users.collection('domaingroups').deleteOne({ domain: tools.normalizeDomain(result.value.domain) });
            } catch (err) {
                res.status(500);
                return res.json({
                    error: 'MongoDB Error: ' + err.message,
                    code: 'InternalDatabaseError'
                });
            }

            return res.json({
                success: true
            });
        })
    );
};
