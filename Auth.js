var _ = require('lodash'),
    util = require('../helpers/utilities.js'),
    models = require('../models'),
    crypto = require('crypto');

function Auth(id, req, res) {
    if(id && req) {
        this.init(id, req, res);
    }
}

Auth.prototype.init = function(id, req, res) {
    this.id = id;
    this.req = req;
    this.res = res;
    this.uexpire = 3600;

    this.cookie = req.signedCookies[id];
};

Auth.prototype.isSSL = function() {
    return !!this.req.connection.encrypted;
};


Auth.prototype.email_exists =function(email) {
    if(email) {
        let users = models.models.user.find({
            email: email
        });

        if(! util.empty(users)) {
            for(let i = 0; i < users.length; i++) {
                if(users[i].email === email.toString().trim()) {
                    return users[i].id;
                }
            }
        }
    }

    return false;
};

Auth.prototype.generateCookie = function(user_id, remember) {
    var value, hash, key,
        expiration = 0,
        expire = 0,
        date = new Date(),
        user = models.models.user.find(user_id),
        params = {
            path: this.req.baseUrl,
            signed: true
        };

    if(util.empty(user_id)) {
        return false;
    }

    remember = remember ? remember : false;

    if(util.empty(remember)) {  // not remembered
        expire = this.uexpire;
        expiration = date.getTime() + expire;
        params.expires = new Date(Date.now() + (expire * 1000));
    }

    key = crypto.createHmac('md5', 'auth').update(user.email + '|' + expiration).digest('hex');
    hash = crypto.createHmac('sha1', key).update(user.email + '|' + expiration).digest('hex');

    value = user.email + '|' + expiration + '|' + hash;

    return {
        value: value,
        params: params
    };
};

// extend login cookie expiration to uexpire from current time
Auth.prototype.refreshCookie = function(user) {
    var cookie = this.req.signedCookies[this.id],
        [email, expiration, hash] = cookie.split('|'),
        date = new Date(),
        params = {
            path: this.req.baseUrl,
            signed: true
        },
        expire = 0,
        key, value;

    if(expiration > 0) {
        // extend expiration
        if(date.getTime() > expiration) {
            expire = this.uexpire;
        }

        expiration = date.getTime() + expire;

        if(expire) {
            params.expires = new Date(Date.now() + (expire * 1000));
        }

        key = crypto.createHmac('md5', 'auth').update(user.email + '|' + expiration).digest('hex');
        hash = crypto.createHmac('sha1', key).update(user.email + '|' + expiration).digest('hex');
        value = user.email + '|' + expiration + '|' + hash;

        this.res.cookie(this.id, value, params);  // set cookie value & args

        // for admin
        params.path = '/api/v1/admin';
        this.res.cookie(this.id, value, params);  // set cookie value & args
    }
};

Auth.prototype.getUser = function() {
    if(! util.empty(this.cookie)) {
        [email, expiration, hash] = this.cookie.split('|');

        let user, users = models.models.user.find({
            email: email
        });

        if(users.length) {
            let key = crypto.createHmac('md5', 'auth').update(email + '|' + expiration).digest('hex');
            user = users[0];

            if(hash === crypto.createHmac('sha1', key).update(user.email + '|' + expiration).digest('hex')) {
                return user;
            }
        }
    }

    return false;
};

Auth.prototype.isUserLoggedIn = function() {
    const user = this.getUser();

    if(user) {
        this.refreshCookie(user);
    } else {
        // clean-up
        this.signOut();
    }

    return !!user;
};

Auth.prototype.signIn = function(userid, remember, params) {
    if(userid) {
        let cookie, user = models.models.user.find(userid);

        if(! util.empty(user.status)) { // heck status
            cookie = this.generateCookie(userid, ! util.empty(remember));

            this.res.cookie(this.id, cookie.value, _.extend(cookie.params, params));  // set cookie value & args

            // for admin
            cookie.params.path = '/api/v1/admin';
            this.res.cookie(this.id, cookie.value, _.extend(cookie.params, params));  // set cookie value & args

            return true;
        }
    }

    return false;
};

Auth.prototype.signOut = function() {
    this.res.clearCookie(this.id, {
        path: this.req.baseUrl
    });
};

module.exports = Auth;