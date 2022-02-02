var MSG={"app":"Leanote","share":"Compartir","noTag":"Sin etiquetas","inputUsername":"ingrese nombre de usuarios","inputEmail":"Es requerido el Email ","inputPassword":"Requerida la contraseña","inputPassword2":"Introduzca de nuevo la nueva contraseña","confirmPassword":"Las contraseñas no coinciden","history":"Historial","editorTips":"Consejos","editorTipsInfo":"<h4>1. Atajos</h4>ctrl+shift+c Cambiar a código<h4>2. shift+enter Salir del bloque actual</h4> eg. <img src=\"/images/outofcode.png\" style=\"width: 90px\"/> en esta situación puede usar shift + enter para salir del bloque de código actual.","all":"Reciente","trash":"Papelera","delete":"Eliminar","unTitled":"Sin título","defaultShare":"Compartir predeterminado","writingMode":"Modo de escritura","normalMode":"Modo normal","saving":"Guardando","saveSuccess":"Guardado exítoso","update":"Actualizar","close":"Cerrar","cancel":"Cancelar","send":"Enviar","shareToFriends":"Compartir a los amigos","publicAsBlog":"Publicar como blog","cancelPublic":"Cancelar publicación","setBlogTop":"Blog anclado en la parte superior","cancelBlogTop":"Desanclar blog","move":"Mover","copy":"Copiar","rename":"Renombrar","exportPdf":"Exportar como PDF","addChildNotebook":"Agregar cuaderno secundario","deleteAllShared":"Eliminar compartir con usuario","deleteSharedNotebook":"Eliminar compartir cuaderno","copyToMyNotebook":"Copiar a mi cuaderno","checkEmail":"Verifique el correo electrónico","sendVerifiedEmail":"Envia un correo electrónico de verificación","friendEmail":"Email de amigo","readOnly":"Sólo lectura","writable":"Escritura","inputFriendEmail":"Requerido el email del amigo","clickToChangePermission":"Clic para cambiar los permisos","sendInviteEmailToYourFriend":"Enviar invitación al email de su amigo","friendNotExits":"Tu amigo no tiene la cuenta de %s's, invita a registrarse en el enlace: %s","emailBodyRequired":"Requerido el mensaje del Email","sendSuccess":"exítoso","inviteEmailBody":"Hola,Yo soy %s, %s es impresionante, venga!","historiesNum":"Hemos ahorrado como máximo <b>10</b> últimas historias con cada nota","noHistories":"Sin historial","datetime":"Fecha y hora","restoreFromThisVersion":"Restaurar desde esta versión","confirmBackup":"¿Está seguro de restaurar desde esta versión? Vamos a hacer una copia de seguridad de la nota actual.","createAccountSuccess":"Cuenta creada correctamente","createAccountFailed":"Creación de cuenta fallido","updateUsernameSuccess":"Nombre de usuario actualizado","usernameIsExisted":"Nombre de usuario ya existe","noSpecialChars":"nombre de usuario no puede contener caracteres especiales","minLength":"La longitud es al menos %s","errorEmail":"Introduzca un correo electrónico correcto","verifiedEmaiHasSent":"El correo electrónico de verificación se ha enviado, compruebe su correo electrónico.","emailSendFailed":"Envió de Email fallido","inputNewPassword":"Requerida la nueva contraseña","errorPassword":"La longitud de la contraseña es al menos 6 caracteres y asegúrese de ser lo más compleja posible","updatePasswordSuccess":"Actualización de contraseña correcta","Please save note firstly!":"Por favor primero guarde la nota!","Please sign in firstly!":"Por favor primero inicie sesión!","Are you sure ?":"Está seguro?","Are you sure to install it ?":"Está seguro de instalar?","Are you sure to delete":"está seguro para eliminar?","Success":"Exítoso","Error":"Error","File exists":"Archivo existe","Delete file":"Eliminar archivo","No images":"Sin imágenes","Filename":"Nombre de archivo","Group Title":"Título del grupo","Hyperlink":"Enlace Web","Please provide the link URL and an optional title":"Proporcione la URL del enlace y un título opcional","optional title":"título opcional","Cancel":"Cancelar","Strong":"Negrilla","strong text":"texto en negrilla","Emphasis":"Cursiva","emphasized text":"texto en cursiva","Blockquote":"Bloque de código","Code Sample":"Código","enter code here":"ingrese aquí el código ","Image":"Imagen","Heading":"Encabezado","Numbered List":"Lista numerada","Bulleted List":"Lista de viñetas","List item":"Elemento de lista","Horizontal Rule":"Regla horizontal","Markdown syntax":"Sintaxis Markdown ","Undo":"Deshacer","Redo":"Rehacer","enter image description here":"ingrese aquí la descripción de imagen","enter link description here":"ingrese aquí descripción del enlace Web","Edit mode":"Modo edición","Vim mode":"Modo Vim","Emacs mode":"Modo Emacs ","Normal mode":"Modo normal","Normal":"Normal","Light":"Liviano","Light editor":"Editor liviano","Add Album":"Añadir álbum","Cannot delete default album":"No puede eliminar el álbum predeterminado","Cannot rename default album":"No puede renombrar el álbum predeterminado","Rename Album":"Renombrar álbum","Add Success!":"Añadido correctamente!","Rename Success!":"Renombrado correctamente!","Delete Success!":"Eliminado correctamente!","Are you sure to delete this image ?":"Está seguro que desea eliminar esta imagen?","click to remove this image":"clic para eliminar esta imagen","error":"error","Prev":"Anterior","Next":"Siguiente"};function getMsg(key, data) {var msg = MSG[key];if(msg) {if(data) {if(!isArray(data)) {data = [data];}for(var i = 0; i < data.length; ++i) {msg = msg.replace("%s", data[i]);}}return msg;}return key;}