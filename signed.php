<?php

$ga_property = 'UA-XXX-1';
$hmac_private_key = "yoursecretkey";

# create signed request of UA, Host, URL, request_time
$request_to_sign = $_SERVER['HTTP_USER_AGENT'] . ":" . $_SERVER['HTTP_HOST'] . ":" . $_SERVER['REQUEST_URI'] . ":" . $_SERVER['REQUEST_TIME'];

$hmac_sig = base64_encode(hash_hmac('sha256', $request_to_sign, $hmac_private_key, true));

?>
<script>
  (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
  (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
  m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
  })(window,document,'script','https://www.google-analytics.com/analytics.js','ga');

ga('create', '<?php echo $ga_property;?>', 'auto');

// from: https://developers.google.com/analytics/devguides/collection/analyticsjs/tasks#adding_to_a_task
ga(function(tracker) {

    // Modifies sendHitTask to send the request to a local server instead of GA
    tracker.set('sendHitTask', function(model) {
        var xhr = new XMLHttpRequest();
        var postdata = model.get('hitPayload');
        postdata = postdata + "&request_time=<?php echo $_SERVER['REQUEST_TIME']; ?>&hmac_sig=<?php echo urlencode($hmac_sig);?>&uri=<?php echo urlencode($_SERVER['REQUEST_URI']);?>";
        xhr.open('POST', '/signedproxy.php', true);
        xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        xhr.send(postdata);
        console.log(xhr.responseText);
    });
});

ga('send', 'pageview');
</script>
