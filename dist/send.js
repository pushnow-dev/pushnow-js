import { uploadAttachment, validateAttachmentData, validateAttachmentMetadata } from './attachments.js';
import { validateConfig } from './config.js';
import { prepareMessageV2, submitMessageV2, validateContent, validateMessageOptions } from './messages.js';
import { recipientsV2 } from './recipients.js';
export async function sendNotification(input, notification, inputOptions = {}) {
    const config = validateConfig(input), options = { ...inputOptions, ...validateMessageOptions(inputOptions) };
    const { files = [], image, icon, ...content } = notification;
    const full = validateContent(content);
    if (!Array.isArray(files))
        throw new Error('files must be an array');
    if ((image && full.image_id) || (icon && full.icon_id))
        throw new Error('Choose a file upload or an existing attachment ID');
    const uploads = [...files, ...(image ? [image] : []), ...(icon ? [icon] : [])].map(file => {
        const meta = validateAttachmentMetadata(file);
        validateAttachmentData(file.data);
        return { ...meta, data: file.data };
    });
    if (full.attachments.length + uploads.length > 20)
        throw new Error('Maximum 20 attachments per notification');
    const knownIDs = [...full.attachments.map(a => a.id), ...uploads.flatMap(a => a.id ? [a.id] : [])];
    if (new Set(knownIDs).size !== knownIDs.length)
        throw new Error('Duplicate attachment');
    const directory = await recipientsV2(config, options);
    if (options.deviceIds?.some(id => !directory.devices.some(d => d.id === id)))
        throw new Error('Unknown notification device');
    for (let index = 0; index < uploads.length; index++) {
        const file = uploads[index];
        const descriptor = await uploadAttachment(config, file.data, file, options);
        full.attachments.push(descriptor);
        if (image && index === files.length)
            full.image_id = descriptor.id;
        if (icon && index === files.length + (image ? 1 : 0))
            full.icon_id = descriptor.id;
    }
    const message = await prepareMessageV2(config, directory, full, options);
    return submitMessageV2(config, message, options);
}
