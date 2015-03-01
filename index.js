/**!
 * ali-baseclient - index.js
 *
 * Copyright(c) ali-sdk and other contributors.
 * MIT Licensed
 *
 * Authors:
 *   fengmk2 <m@fengmk2.com> (http://fengmk2.com)
 */

"use strict";

/**
 * Module dependencies.
 */

var debug = require('debug')('ali-sdk:baseclient');
var urllib = require('urllib');
var crypto = require('crypto');

function BaseClient(type, options) {
  this._type = type.toLowerCase();
  this._TYPE = type.toUpperCase();
  if (!options
    || !options.accessKeyId
    || !options.accessKeySecret) {
    throw new TypeError('require accessKeyId, accessKeySecret');
  }

  this.options = options;
}

var proto = BaseClient.prototype;

/**
 * set Authorization header
 *
 * @param {String} method
 * @param {String} resource
 * @param {Object} header
 */

proto.setAuthorization = function (method, canonicalizedResource, headers) {
  // Authorization: $TYPE + ' ' + $AccessKeyId + ':' + $Signature
  var auth = this._TYPE + ' ' + this.options.accessKeyId + ':' +
    this.signature(method, canonicalizedResource, headers);
  headers.Authorization = auth;
};

/**
 * get Signature
 *
 * Signature = base64(hmac-sha1(Access Key Secret + "\n"
 *  + VERB + "\n"
 *  + CONTENT-MD5 + "\n"
 *  + CONTENT-TYPE + "\n"
 *  + DATE + "\n"
 *  + CanonicalizedOSSHeaders
 *  + CanonicalizedResource))
 *
 * @param {String} method
 * @param {String} resource
 * @param {Object} header
 */
proto.signature = function (method, canonicalizedResource, headers) {
  // VERB + "\n"
  // + CONTENT-MD5 + "\n"
  // + CONTENT-TYPE + "\n"
  // + DATE + "\n"
  // + CanonicalizedHeaders + "\n"
  // + CanonicalizedResource
  var params = [
    method.toUpperCase(),
    headers['Content-Md5'] || headers['Content-MD5'] || '',
    headers['Content-Type'] || '',
    headers.Date || new Date().toGMTString()
  ];

  var canonicalizedHeaders = {};
  var canonicalizedPrefix = 'x-' + this._type + '-';
  for (var key in headers) {
    var lkey = key.toLowerCase().trim();
    if (lkey.indexOf(canonicalizedPrefix) === 0) {
      canonicalizedHeaders[lkey] = canonicalizedHeaders[lkey] || [];
      canonicalizedHeaders[lkey].push(String(headers[key]).trim());
    }
  }

  var canonicalizedHeadersList = [];
  Object.keys(canonicalizedHeaders).sort().forEach(function (key) {
    canonicalizedHeadersList.push(key + ':' + canonicalizedHeaders[key].join(','));
  });

  params = params.concat(canonicalizedHeadersList);

  // TODO: support sub resource
  params.push(canonicalizedResource);

  var stringToSign = params.join('\n');
  var signature = crypto.createHmac('sha1', this.options.accessKeySecret);
  signature = signature.update(stringToSign).digest('base64');
  debug('authorization stringToSign: %j, signature: %j',
    stringToSign, signature);
  return signature;
};
