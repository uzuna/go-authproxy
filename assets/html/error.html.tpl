<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1">

	<title>{{.Code}}:{{.Message}}</title>
    <link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/semantic-ui/2.4.1/semantic.min.css"></link>
    <style type="text/css">
        body {
        background-color: #DADADA;
        }
        body > .grid {
        height: 100%;
        }
        .image {
        margin-top: -100px;
        }
        .column {
        max-width: 600px;
        }
        .masthead h1.ui.header {
            font-size: 7em;
            font-weight: normal;
        }
        .masthead h2 {
        font-size: 3em;
        font-weight: normal;
        }
    </style>
</head>

<body>
    <div class="ui middle aligned center aligned grid masthead">
        <div class="column">
            <h1 class="ui header">{{.Code}}</h1>
            <h2  class="ui header">{{.Message}}</h2>
            <p>
                <a class="ui labeled icon button blue" href="/">
                    <i class="angle double up icon"></i>
                    Go to Top
                </a>
                <a class="ui labeled icon button teal" href="/login">
                    <i class="sign-in icon"></i>
                    Sign In
                </a>
            </p>
        </div>
    </div>
</body>
</html>
