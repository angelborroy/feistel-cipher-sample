# Use official OpenJDK 11 image
FROM openjdk:11-jdk-slim

# Set working directory
WORKDIR /app

# Copy source code
COPY src/ ./src/

# Compile the Java application
RUN javac src/es/usj/crypto/cipher/FeistelCipherApp.java

# Set the classpath
WORKDIR /app/src

# Default command runs with default plaintext
CMD ["java", "-cp", ".", "es.usj.crypto.cipher.FeistelCipherApp"]