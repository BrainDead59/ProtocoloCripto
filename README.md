# Protocolo Cripto
Este proyecto connsiste en el desarrollo de un protocolo de comunicación simple simulado, mediante el uso del lenguaje python y el framework streamlit.

## Integrantes

- Díaz Hernández Marcos Bryan
- Fernández Rosales Sebastián
- Medina Segura Fernando 
- Robledo Aguirre Eduardo 
- Toledo Sánchez Roberto


## Algoritmos implementados
- Simetrico: AES
- Generar llaves: RSA(2048)
- Asimetrico: RSA - PKCS1_OAEP
- Key Derivation: Scrypt
- Firmado: RSA - PKCS115_SigScheme
- KEM: RSA - PKCS1_OAEP

## Modo de uso

Dirigirse al siguiente link: https://protocolocripto.streamlit.app/, se abrira la interfaz gráfica de simulación, donde se podra visualizar el usuario que comienza la conversación.

### Interfaz de inicio

- Para cada usuario se pueden generar las llaves públicas y privadas.
- Se deben de colocar las llaves que correspondan, en los drag and drop.
- Al colocar las llaves tanto publica y privada se debera de poder iniciar el chat entre las dos entidades simuladas.

### Interfaz de chat

 - Dentro de la interfaz se tendran tres secciones de interaccion, primero se deberan de colocar las respectivas credenciales de cada usuario, y la llave que corresponda en base a la indicación.
  - Al tener las llaves correspondientes, se habilitara el chat entre los usuarios y se podran enviar y recibir mensajes.