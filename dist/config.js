import { decode, object, uuid } from './encoding.js';
export function validateAPIURL(value) {
    const url = new URL(value);
    if (url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
        (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) {
        throw new Error('Use an HTTPS API origin (HTTP is allowed only on localhost)');
    }
    return url.origin;
}
export function validateArchive(value) {
    const archive = object(value);
    uuid(archive.id);
    decode(archive.public_key, 65);
    decode(archive.certificate, 64);
    return { id: archive.id, public_key: archive.public_key, certificate: archive.certificate };
}
/** Structural validation only. finishLogin pins identity; recipientsV2 verifies signed bindings. */
export function validateConfig(value) {
    const config = object(value);
    for (const field of ['api_url', 'user_id', 'source_id', 'source_key', 'identity_public_key', 'sender_private_key']) {
        if (typeof config[field] !== 'string' || !config[field] || /[\r\n]/.test(config[field]))
            throw new Error(`Missing or invalid config field: ${field}`);
    }
    uuid(config.user_id);
    uuid(config.source_id);
    if (!/^[\x21-\x7e]{1,2048}$/.test(config.source_key))
        throw new Error('Invalid source credential');
    decode(config.identity_public_key, 65);
    decode(config.sender_private_key, 32);
    return { api_url: validateAPIURL(config.api_url), user_id: config.user_id, source_id: config.source_id,
        source_key: config.source_key, identity_public_key: config.identity_public_key,
        sender_private_key: config.sender_private_key, archive: validateArchive(config.archive) };
}
