# PhPass
A rust implementation of the password hashing algorithm used by WordPress. https://www.openwall.com/phpass/

## What
WordPress, the most popular blogging platform of all time, is the main application of the PhPass password algorithm. Since WP is nothing if not broad and backwards-compatible in its support, they avoided using a more modern checksum (e.g. SHA256) in favour of old-fashioned, long-broken md5. To make up for this, they'll run MD5 on a salted (and re-salted) input 256 times.

## Why
We often don't know which ideas and projects will become successful when we make them, and frequently sites evolve naturally from a simple, managed WordPress blog, to one with a custom plugin, to a hosted PHP app with WordPress as one of its packages, to away from PHP entirely. Those who move to rust (which is wonderful) will want some way to keep those old logins working.

It's also considerably faster than the native PHP version, so could be used in quickly auditing your WordPress user database, to flag and disable accounts with insecure (easy to guess) passwords.

## How
This crate provides the basics to decode the PhPass checksum and salt from the standard WordPress hash string, and verify against a cleartext password.

TODO: proper rustdoc and an examples dir

### Getting started

```rs
    // mysql_async querying our user's hash
    let hash: String = pool
        .get_conn()
        .await?
        .first_exec(
            "SELECT user_pass FROM wp_users WHERE user_email = ?;",
            vec![&auth_data.email],
        )
        .await?
        .1
        .ok_or(MyError)?;

    // Return on failed verify through the beauty of ?
    PhPass::try_from(hash)?.verify(&auth_data.password)?;
```
