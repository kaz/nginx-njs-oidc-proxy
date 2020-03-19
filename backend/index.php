<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
	</head>
	<body>
		<table border="1">
			<tr>
				<th>PHP_AUTH_USER</th>
				<th>HTTP_X_USER_EMAIL</th>
			</tr>
			<tr>
				<td><?= $_SERVER["PHP_AUTH_USER"] ?></td>
				<td><?= $_SERVER["HTTP_X_USER_EMAIL"] ?></td>
			</tr>
		</table>
	</body>
</html>
