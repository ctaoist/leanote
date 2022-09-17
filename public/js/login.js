/**
 * Date: 2022/7/30
 */
$(function () {
    Fingerprint.useClientID(true).then(function () {
        if ( !document.cookie.match(/&?keepalive=/) ) {
            return;
        }

        $.post("/cookie/login").then(function (res) {
            if ( res.Ok ) {// 跳转到首页
                location.href = '/'
            }
        });
    });
})