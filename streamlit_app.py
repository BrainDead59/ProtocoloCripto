from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import streamlit as st
import scrypt
import os

#Se configura la página
st.set_page_config(
    page_title="XS",
    page_icon=":cyclone:",
    layout="wide",  
    initial_sidebar_state="collapsed"
)

#Se definen las variables globales para identificar el estado de la conexión y los mensajes
global generaConexionUserA, generaConexionUserB, mensajeBuzonA, mensajeBuzonB
mensajeBuzonA = False
mensajeBuzonB = False
generaConexionUserA = False
generaConexionUserB = False

#Se define la variable de sesión, para iniciar la conexión
if 'sesion' not in st.session_state:
    st.session_state.sesion = None

#Se definen las funciones para el cifrado simetrico AES y descifrado de mensajes, con la llave de sesión
def encriptarMensajeAES(llave, mensaje):
    cifrado = AES.new(llave, AES.MODE_EAX)
    nonce = cifrado.nonce
    textoCifrado, tag = cifrado.encrypt_and_digest(mensaje)
    return nonce, textoCifrado, tag

#Se define la función para desencriptar el mensaje AES, con la llave de sesión y el mensaje cifrado
def desencriptarMensajeAES(nonce, llave, textoCifrado, tag):
    cifrado = AES.new(llave, AES.MODE_EAX, nonce=nonce)
    textoPlano = cifrado.decrypt(textoCifrado)
    try:
        cifrado.verify(tag)
        return textoPlano
    except (ValueError, TypeError):
        return False

#Se definen las funcion para el cifrado de la llave de sesión con PKCS1_OAEP, con la llave pública del usuario
#https://cryptobook.nakov.com/asymmetric-key-ciphers/rsa-encrypt-decrypt-examples
def RSAEncriptarKEM(llavePublicaUsuario, llaveSimetrica):
    cifradoRSA = PKCS1_OAEP.new(RSA.importKey(llavePublicaUsuario.getvalue()))
    try:
        llaveCifrada = cifradoRSA.encrypt(llaveSimetrica)
        return llaveCifrada
    except (ValueError, TypeError):
        st.write('Error al cifrar la llave de sesión')
        st.write(ValueError)
        st.write(TypeError)

#Se define la función para el descifrado de la llave de sesión con PKCS1_OAEP, con la llave privada del usuario
def RSADesencriptarKEM(llavePrivadaUsuario, llaveCifrada, contra):
    try:
        cifradoRSA = PKCS1_OAEP.new(RSA.importKey(llavePrivadaUsuario.getvalue(), contra))
        llave = cifradoRSA.decrypt(llaveCifrada)
        return llave
    except (ValueError, TypeError):
        st.write('Error al descifrar la llave de sesión')
        st.write(ValueError)
        st.write(TypeError)

#Se define la función para firmar el mensaje usando PKCS115_SigScheme, con la llave privada del usuario
#https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples
def firmaHash(mensajeUsuario, llavePrivadaUsuario,contraUsuario):
    try:
        llaveImportadaUsuario = RSA.import_key(llavePrivadaUsuario.getvalue(),contraUsuario)
        hash = SHA256.new(mensajeUsuario.encode())
        firma = PKCS115_SigScheme(llaveImportadaUsuario)
        firmaUsuario = firma.sign(hash)
        return firmaUsuario, hash
    except (ValueError, TypeError):
        st.write('Error al firmar el mensaje')
        st.write(ValueError)
        st.write(TypeError)

#Se define la función para verificar la firma del mensaje usando PKCS115_SigScheme, con la llave pública del usuario
def verificaHash(hashMensaje, firmaHash, llavePublicaUsuario):
    llavePublicaUsuario = RSA.import_key(llavePublicaUsuario.getvalue())
    verificaUsuarioA = PKCS115_SigScheme(llavePublicaUsuario)

    try:
        verificaUsuarioA.verify(hashMensaje, firmaHash)
        return hashMensaje
    except (ValueError, TypeError):
        return False

#Se define la función para generar un salt aleatorio
def generarSalt():
    salt = os.urandom(16)
    return salt

#Se define la función para cifrar la llave de sesión, con un salt aleatorio
#https://cryptobook.nakov.com/mac-and-key-derivation/scrypt
def cifradoLlaveSimetricaSalt(secreto):
    saltSesion = generarSalt()
    secretoCodificado = secreto
    try:
        llaveSecretoCompartido = scrypt.hash(secretoCodificado, saltSesion, 2048, 8, 1, 32) #256 bits
        return llaveSecretoCompartido
    except (ValueError, TypeError):
        st.write('Error al cifrar la llave de sesión')
        st.write(ValueError)
        st.write(TypeError)

#Se define la función para compartir las llaves RSA, con el usuario usando RSA
@st.cache_data
def crearLlavesRSA(contraPrivada):
    llavesParesUsuario = RSA.generate(2048)
    llavePublicaUsuario = llavesParesUsuario.publickey()
    llavePublicaUsuarioPEM = llavePublicaUsuario.exportKey('PEM')
    llavePrivadaUsuarioPEM = llavesParesUsuario.exportKey('PEM',contraPrivada)

    return llavePublicaUsuarioPEM, llavePrivadaUsuarioPEM

#Se define la función para descargar las llaves RSA, con el usuario
def descargaLLavesUsuario(llavePublicaUsuarioPEM, llavePrivadaUsuarioPEM, llavesUsuario, usuario):
    if usuario == 'A':
        llavesUsuario.download_button('Descargar clave pública usuario A', llavePublicaUsuarioPEM, 'llavePublicaUsuarioA.pem')
        llavesUsuario.download_button('Descargar clave privada usuario A', llavePrivadaUsuarioPEM, 'llavePrivadaUsuarioA.pem')
    
    if usuario == 'B':
        llavesUsuario.download_button('Descargar clave pública usuario B', llavePublicaUsuarioPEM, 'llavePublicaUsuarioB.pem')
        llavesUsuario.download_button('Descargar clave privada usuario B', llavePrivadaUsuarioPEM, 'llavePrivadaUsuarioB.pem')

#Se define la función para cifrar el secreto con PKCS1_OAEP, con la llave publica usando RSA
#https://cryptobook.nakov.com/asymmetric-key-ciphers/rsa-encrypt-decrypt-examples
def cifradoSecretoAsimetrica(llavePublicaUsuario, secreto):
    try:
        cifradoRSA = PKCS1_OAEP.new(RSA.import_key(llavePublicaUsuario.getvalue()))
        secretoCifrado = cifradoRSA.encrypt(secreto.encode())
        return secretoCifrado
    except (ValueError, TypeError):
        st.write('Error al cifrar el secreto')
        st.write(ValueError)
        st.write(TypeError)

#Se define la función para descifrar el secreto con PKCS1_OAEP, con la llave privada usando RSA
def descifradoSecretoAsimetrica(secretoCifrado, columna):
    llavePrivadaUsuarioPEM = columna.file_uploader('Sube tu clave privada', type=['pem'])
    contraPriva = columna.text_input("Inserta tu contraseña para la llave privada:")
    if llavePrivadaUsuarioPEM is not None and contraPriva != "" and len(contraPriva)>=8:
        try:
            cifradoRSA = PKCS1_OAEP.new(RSA.import_key(llavePrivadaUsuarioPEM.getvalue(), contraPriva))
            secreto = cifradoRSA.decrypt(secretoCifrado)
            return secreto
        except (ValueError, TypeError):
            st.write('Error al descifrar el secreto')
            st.write(ValueError)
            st.write(TypeError)

#Se define la función para compartir el secreto, e iniciar el chat
def actualizaAvance(llaveSesion):
    st.session_state.sesion = llaveSesion

#Se define la función para compartir el secreto, y crear la llave de sesión
def compartirSecreto():
    global generaConexionUserA, generaConexionUserB
    secretoCifrado = None

    st.title('Protocolo de intercambio de mensajes seguro')

    usuario = st.selectbox('Selecciona el usuario que deseas simular:', ('Usuario A', 'Usuario B'))

    if 'Usuario A' == usuario:
        indicacionLlavesUsuarioA = st.toggle("Genera llaves para usuario A")

        if indicacionLlavesUsuarioA:
            contraPrivada = st.text_input("A: Inserta tu contraseña para la llave privada, mayor a 8 caracteres:")
            if contraPrivada != "" and len(contraPrivada)>=8:
                #Crea las llaves RSA para el usuario A, con la contraseña
                llavePublicaUsuarioPEM, llavePrivadaUsuarioPEM = crearLlavesRSA(contraPrivada)
                descargaLLavesUsuario(llavePublicaUsuarioPEM, llavePrivadaUsuarioPEM, st, 'A')

        else:
            secreto = st.text_input('A - Inserta el secreto:')
            llavePublicaUsuarioBPEM = st.file_uploader('Sube la clave pública usuario B', type=['pem'], key='RSASecretoPublica')

            if secreto != "" and llavePublicaUsuarioBPEM is not None:
                #Cifra el secreto con la llave pública del usuario B
                secretoCifrado = cifradoSecretoAsimetrica(llavePublicaUsuarioBPEM, secreto)
                generaConexionUserA = True

    if 'Usuario B' == usuario:
        indicacionLlavesUsuarioB = st.toggle("Genera llaves para usuario B")

        if indicacionLlavesUsuarioB:
            contraPrivada = st.text_input("B: Inserta tu contraseña para la llave privada, mayor a 8 caracteres:")
            if contraPrivada != "" and len(contraPrivada)>=8:
                #Crea las llaves RSA para el usuario B, con la contraseña
                llavePublicaUsuarioPEM, llavePrivadaUsuarioPEM = crearLlavesRSA(contraPrivada)
                descargaLLavesUsuario(llavePublicaUsuarioPEM, llavePrivadaUsuarioPEM, st, 'B')

        else:
            secreto = st.text_input('B - Inserta el secreto:')
            llavePublicaUsuarioAPEM = st.file_uploader('Sube la clave pública usuario A', type=['pem'], key='RSASecretoPublica')

            if secreto != "" and llavePublicaUsuarioAPEM is not None:
                #Cifra el secreto con la llave pública del usuario A
                secretoCifrado = cifradoSecretoAsimetrica(llavePublicaUsuarioAPEM, secreto)
                generaConexionUserB = True

    usuarioA, usuarioB = st.columns(2)

    if generaConexionUserA and secretoCifrado != "":
        usuarioB.markdown('## Usuario B')
        #Descifra el secreto con la llave privada del usuario B
        secretoRecibido = descifradoSecretoAsimetrica(secretoCifrado, usuarioB)
        if secretoRecibido is not None:
            #Cifra la llave de sesión con un salt aleatorio
            iniciaChatLlave = cifradoLlaveSimetricaSalt(secretoRecibido)
            if iniciaChatLlave is not None:
                usuarioB.button('Iniciar chat', on_click=actualizaAvance(iniciaChatLlave))

    if generaConexionUserB and secretoCifrado != "":
        usuarioA.markdown('## Usuario A')
        #Descifra el secreto con la llave privada del usuario A
        secretoRecibido = descifradoSecretoAsimetrica(secretoCifrado, usuarioA)
        if secretoRecibido is not None:
            #Cifra la llave de sesión con un salt aleatorio
            iniciaChatLlave = cifradoLlaveSimetricaSalt(secretoRecibido)
            if iniciaChatLlave is not None:
                usuarioA.button('Iniciar chat', on_click=actualizaAvance(iniciaChatLlave))

#Se define la función para iniciar el chat, con la llave de sesión
def iniciaChat(llaveSesion):
    usuarioASuite, usuarioBSuite = st.columns(2)
    global mensajeBuzonA, mensajeBuzonB

    nonceA, ciphertextA, tagA = None, None, None
    nonceB, ciphertextB, tagB = None, None, None
    llaveSesionEncriptadaParaB = None
    llaveSesionEncriptadaParaA = None
    recibirMensajeUsuarioA = None
    recibirMensajeUsuarioB = None
    contraUsuarioA = None
    contraUsuarioB = None
    hashMensajeUsuarioAFirmado = None
    hashMensajeUsuarioBFirmado = None
    hashMensajeUsuarioA = None
    hashMensajeUsuarioB = None

    usuarioASuite.markdown('## Usuario A')
    usuarioBSuite.markdown('## Usuario B')

    enviarMensajeUsuarioA, recibirMensajeUsuarioA, archivosUsuarioA = usuarioASuite.tabs(["Enviar Mensaje", "Mensaje Recibido","Subir Archivos"])
    enviarMensajeUsuarioB, recibirMensajeUsuarioB, archivosUsuarioB = usuarioBSuite.tabs(["Enviar Mensaje", "Mensaje Recibido","Subir Archivos"])

    #Se definen los campos para subir las llaves de los usuarios
    llavePrivadaUsuarioAPEM = archivosUsuarioA.file_uploader('Sube la clave privada usuario A', type=['pem'])
    contraUsuarioA = archivosUsuarioA.text_input("Inserta tu contraseña para la llave privada:", key="contraUsuarioA")

    llavePrivadaUsuarioBPEM = archivosUsuarioB.file_uploader('Sube la clave privada usuario B', type=['pem'])
    contraUsuarioB = archivosUsuarioB.text_input("Inserta tu contraseña para la llave privada:", key="contraUsuarioB")

    llavePublicaUsuarioBPEM = archivosUsuarioA.file_uploader('Sube la clave pública usuario B', type=['pem'])
    llavePublicaUsuarioAPEM = archivosUsuarioB.file_uploader('Sube la clave pública usuario A', type=['pem'])

    if llavePrivadaUsuarioAPEM is not None and contraUsuarioA != "" and len(contraUsuarioA)>=8 and llavePrivadaUsuarioBPEM is not None and contraUsuarioB != "" and len(contraUsuarioB)>=8:
        if llavePublicaUsuarioBPEM is not None and llavePublicaUsuarioAPEM is not None:

            mensajeUsuarioA = enviarMensajeUsuarioA.text_input('Mensaje para usuario B:')
            mensajeUsuarioB = enviarMensajeUsuarioB.text_input('Mensaje para usuario A:')

            if mensajeUsuarioA != "":
                    #Se cifra el mensaje con AES y la llave de sesion
                    nonceA, ciphertextA, tagA = encriptarMensajeAES(llaveSesion, mensajeUsuarioA.encode())
                    #Se encripta la llave de sesion con la llave publica del usuario B
                    llaveSesionEncriptadaParaB = RSAEncriptarKEM(llavePublicaUsuarioBPEM, llaveSesion)
                    #Se firma el mensaje con la llave privada del usuario A
                    hashMensajeUsuarioAFirmado, hashMensajeUsuarioA = firmaHash(mensajeUsuarioA, llavePrivadaUsuarioAPEM, contraUsuarioA)
                    mensajeBuzonB = True

            if mensajeUsuarioB != "":
                    #Se cifra el mensaje con AES y la llave de sesion
                    nonceB, ciphertextB, tagB = encriptarMensajeAES(llaveSesion, mensajeUsuarioB.encode())
                    #Se encripta la llave de sesion con la llave publica del usuario A
                    llaveSesionEncriptadaParaA = RSAEncriptarKEM(llavePublicaUsuarioAPEM, llaveSesion)
                    #Se firma el mensaje con la llave privada del usuario B
                    hashMensajeUsuarioBFirmado, hashMensajeUsuarioB = firmaHash(mensajeUsuarioB, llavePrivadaUsuarioBPEM, contraUsuarioB)
                    mensajeBuzonA = True

            if mensajeBuzonA == True:
                #Se desencripta el mensaje con AES, se desencripta la llave de sesion con la llave privada del usuario A y se verifica el mensaje con la publica de B
                estadoEncriptacionMensajeA = desencriptarMensajeAES(nonceB, RSADesencriptarKEM(llavePrivadaUsuarioAPEM, llaveSesionEncriptadaParaA, contraUsuarioA), ciphertextB, tagB)
                estadoMensajeUsuarioA = verificaHash(hashMensajeUsuarioB, hashMensajeUsuarioBFirmado, llavePublicaUsuarioBPEM)
            
                #Se comprueba si el mensaje ha sido alterado, verificando el hash de la desencriptacion con el resultado de la verificación y se muestra el mensaje
                if (estadoMensajeUsuarioA != False) and (estadoEncriptacionMensajeA != False) and (estadoMensajeUsuarioA.digest() == SHA256.new(estadoEncriptacionMensajeA).digest()):
                    recibirMensajeUsuarioA.write('El mensaje ha sido verificado correctamente')
                    recibirMensajeUsuarioA.text_area("Chat con usuario B", 'B: ' + estadoEncriptacionMensajeA.decode(), height=10, disabled=True)
                else:
                    recibirMensajeUsuarioA.write('El mensaje no ha sido verificado correctamente, el mensaje ha sido alterado')

            if mensajeBuzonB == True:
                #Se desencripta el mensaje con AES, se desencripta la llave de sesion con la llave privada del usuario B y se verifica el mensaje con la publica de A
                estadoEncriptacionMensajeB = desencriptarMensajeAES(nonceA, RSADesencriptarKEM(llavePrivadaUsuarioBPEM, llaveSesionEncriptadaParaB, contraUsuarioB), ciphertextA, tagA)
                estadoMensajeUsuarioB = verificaHash(hashMensajeUsuarioA, hashMensajeUsuarioAFirmado, llavePublicaUsuarioAPEM)
            
                #Se comprueba si el mensaje ha sido alterado y se muestra el mensaje
                if (estadoMensajeUsuarioB != False) and (estadoEncriptacionMensajeB != False) and (estadoMensajeUsuarioB.digest() == SHA256.new(estadoEncriptacionMensajeB).digest()):
                    recibirMensajeUsuarioB.write('El mensaje ha sido verificado correctamente')
                    recibirMensajeUsuarioB.text_area("Mensaje recibido", 'A: ' + estadoEncriptacionMensajeB.decode(), height=10, disabled=True)
                else:
                    recibirMensajeUsuarioB.write('El mensaje no ha sido verificado correctamente, el mensaje ha sido alterado')

#Se define la función principal de ejecución
if __name__ == '__main__':
    if st.session_state.sesion == None:
        compartirSecreto()
    elif st.session_state.sesion != None:
        iniciaChat(st.session_state.sesion)

# https://cryptobook.nakov.com/encryption-symmetric-and-asymmetric
# https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
# https://docs.streamlit.io/library/advanced-features/multipage-apps/custom-navigation