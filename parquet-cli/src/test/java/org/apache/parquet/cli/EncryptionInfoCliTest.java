/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.parquet.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.apache.parquet.crypto.ColumnEncryptionProperties;
import org.apache.parquet.crypto.FileEncryptionProperties;
import org.apache.parquet.crypto.ParquetCipher;
import org.apache.parquet.example.data.Group;
import org.apache.parquet.example.data.simple.SimpleGroupFactory;
import org.apache.parquet.hadoop.ParquetWriter;
import org.apache.parquet.hadoop.example.ExampleParquetWriter;
import org.apache.parquet.hadoop.metadata.ColumnPath;
import org.apache.parquet.schema.MessageType;
import org.apache.parquet.schema.MessageTypeParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

class EncryptionInfoCliTest extends CliTestBase {

  private static final byte[] FOOTER_KEY = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
  private static final byte[] COLUMN_KEY = "fedcba9876543210".getBytes(StandardCharsets.UTF_8);
  private static final byte[] KEY_METADATA = {0, (byte) 0xff, 0x41};
  private static final byte[] AAD_PREFIX = {0x12, 0x34};

  @Test
  void reportsUnencryptedFiles() throws Exception {
    Path file = writeFile("plain.parquet", null, 3);
    CliResult result = cli("encryption-info", file.toString());

    assertThat(result.exitCode()).as(result.output()).isZero();
    assertThat(result.output())
        .contains("Footer: plaintext", "Encryption algorithm: none", "  plain: plaintext")
        .contains("  footer: plaintext", "  nested.secret: plaintext")
        .contains("All column chunks use footer key: false")
        .doesNotContain("Encryption algorithm: AES", "Key metadata:");
  }

  @ParameterizedTest
  @EnumSource(ParquetCipher.class)
  void readsCryptoHeaderWithoutDecryptingFooter(ParquetCipher cipher) throws Exception {
    Path file = writeFile(
        "encrypted.parquet",
        FileEncryptionProperties.builder(FOOTER_KEY)
            .withAlgorithm(cipher)
            .withFooterKeyMetadata(KEY_METADATA)
            .withAADPrefix(AAD_PREFIX)
            .build(),
        3);
    CliResult result = cli("encryption-info", file.toString());

    assertThat(result.exitCode()).as(result.output()).isZero();
    assertThat(result.output())
        .contains("Footer: encrypted", "Encryption algorithm: " + cipher)
        .contains("Footer key metadata: present (3 bytes)", "AAD prefix: present (2 bytes)")
        .contains("AAD prefix supplied by reader: false")
        .contains("Authentication: not checked (no decryption keys)")
        .contains("Column encryption: unavailable (encrypted footer)")
        .contains("All column chunks use footer key: unknown (encrypted footer)")
        .doesNotContain("hex=", "Row group", "  plain:");

    CliResult values = cli("encryption-info", "--show-key-metadata", "--show-aad", file.toString());
    assertThat(values.exitCode()).as(values.output()).isZero();
    assertThat(values.output())
        .contains("Footer key metadata: 3 bytes, hex=00ff41", "AAD prefix: 2 bytes, hex=1234");
  }

  @ParameterizedTest
  @EnumSource(ParquetCipher.class)
  void reportsExternalAadWithoutRequestingIt(ParquetCipher cipher) throws Exception {
    Path file = writeFile(
        "external-aad.parquet",
        FileEncryptionProperties.builder(FOOTER_KEY)
            .withAlgorithm(cipher)
            .withAADPrefix(AAD_PREFIX)
            .withoutAADPrefixStorage()
            .build(),
        1);
    CliResult result = cli("encryption-info", "--show-key-metadata", "--show-aad", file.toString());

    assertThat(result.exitCode()).as(result.output()).isZero();
    assertThat(result.output())
        .contains("Footer: encrypted", "Footer key metadata: absent", "AAD prefix: absent")
        .contains("AAD prefix supplied by reader: true")
        .doesNotContain("hex=1234");
  }

  @ParameterizedTest
  @EnumSource(ParquetCipher.class)
  void reportsEveryColumnAndRowGroupInPlaintextFooter(ParquetCipher cipher) throws Exception {
    ColumnPath footer = ColumnPath.fromDotString("footer");
    ColumnPath secret = ColumnPath.fromDotString("nested.secret");
    Path file = writeFile(
        "mixed keys with spaces.parquet",
        FileEncryptionProperties.builder(FOOTER_KEY)
            .withAlgorithm(cipher)
            .withPlaintextFooter()
            .withFooterKeyMetadata(KEY_METADATA)
            .withEncryptedColumns(Map.of(
                footer, ColumnEncryptionProperties.builder(footer).build(),
                secret, ColumnEncryptionProperties.builder(secret)
                    .withKey(COLUMN_KEY)
                    .withKeyMetaData(new byte[0])
                    .build()))
            .build(),
        5);
    CliResult result = cli("encryption-info", file.toString());

    assertThat(result.exitCode()).as(result.output()).isZero();
    assertThat(result.output())
        .contains("Footer: plaintext", "Encryption algorithm: " + cipher)
        .contains("Footer key metadata: present (3 bytes)")
        .contains("Row group 0:", "Row group 1:", "Row group 2:")
        .contains("All column chunks use footer key: false")
        .doesNotContain("hex=");
    assertThat(result.output().split("  plain: plaintext", -1)).hasSize(4);
    assertThat(result.output().split("  footer: footer key", -1)).hasSize(4);
    assertThat(result.output().split("  nested\\.secret: column key", -1)).hasSize(4);
    assertThat(result.output().split("    Key metadata: present \\(0 bytes\\)", -1)).hasSize(4);

    CliResult values = cli("encryption-info", "--show-key-metadata", file.toString());
    assertThat(values.exitCode()).as(values.output()).isZero();
    assertThat(values.output())
        .contains("Footer key metadata: 3 bytes, hex=00ff41", "    Key metadata: 0 bytes, hex=");
  }

  @Test
  void reportsAllColumnsUsingFooterKey() throws Exception {
    Path file = writeFile(
        "footer-key.parquet",
        FileEncryptionProperties.builder(FOOTER_KEY).withPlaintextFooter().build(),
        3);
    CliResult result = cli("encryption-info", file.toString());

    assertThat(result.exitCode()).as(result.output()).isZero();
    assertThat(result.output())
        .contains("  plain: footer key", "  footer: footer key", "  nested.secret: footer key")
        .contains("All column chunks use footer key: true")
        .doesNotContain("  plain: plaintext", "column key");
  }

  @Test
  void doesNotInferColumnEncryptionFromEmptyFooter() throws Exception {
    Path file = writeFile(
        "empty.parquet",
        FileEncryptionProperties.builder(FOOTER_KEY).withPlaintextFooter().build(),
        0);
    CliResult result = cli("encryption-info", file.toString());

    assertThat(result.exitCode()).as(result.output()).isZero();
    assertThat(result.output())
        .contains("Encryption algorithm: AES_GCM_V1", "All column chunks use footer key: unknown (no columns)")
        .doesNotContain("Row group", "  plain:");
  }

  @Test
  void rejectsInvalidMagic() throws Exception {
    byte[] bytes = Files.readAllBytes(writeFile("valid-magic.parquet", null, 1));
    bytes[bytes.length - 1] = '!';
    Path file = getTempFolder().toPath().resolve("bad-magic.parquet");
    Files.write(file, bytes);
    CliResult result = cli("encryption-info", file.toString());

    assertThat(result.exitCode()).isEqualTo(1);
    assertThat(result.output()).contains("Not a Parquet file: invalid tail magic.");
  }

  @ParameterizedTest
  @ValueSource(ints = {0, Integer.MAX_VALUE, -1})
  void rejectsInvalidFooterLengths(int length) throws Exception {
    byte[] bytes = Files.readAllBytes(writeFile("valid-length.parquet", null, 1));
    ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(bytes.length - 8, length);
    Path file = getTempFolder().toPath().resolve("bad-length.parquet");
    Files.write(file, bytes);
    CliResult result = cli("encryption-info", file.toString());

    assertThat(result.exitCode()).isEqualTo(1);
    assertThat(result.output()).contains(length == -1 ? "footer is too large" : "Invalid Parquet footer length");
  }

  @Test
  void rejectsTruncatedFilesAndMultipleInputs() throws Exception {
    Path file = getTempFolder().toPath().resolve("truncated.parquet");
    Files.write(file, new byte[11]);
    CliResult truncated = cli("encryption-info", file.toString());
    assertThat(truncated.exitCode()).isEqualTo(1);
    assertThat(truncated.output()).contains("length is too small");

    CliResult multiple = cli("encryption-info", file.toString(), file.toString());
    assertThat(multiple.exitCode()).isEqualTo(1);
    assertThat(multiple.output()).contains("Exactly one Parquet file is required.");
  }

  private Path writeFile(String name, FileEncryptionProperties encryption, int count) throws Exception {
    Path file = getTempFolder().toPath().resolve(name);
    MessageType schema = MessageTypeParser.parseMessageType("message record {"
        + " required int32 plain; required int32 footer;"
        + " required group nested { required binary secret (STRING); } }");
    SimpleGroupFactory factory = new SimpleGroupFactory(schema);
    ExampleParquetWriter.Builder builder = ExampleParquetWriter.builder(new org.apache.hadoop.fs.Path(file.toUri()))
        .withType(schema)
        .withRowGroupRowCountLimit(2)
        .withMinRowCountForPageSizeCheck(1)
        .withMaxRowCountForPageSizeCheck(1);
    if (encryption != null) {
      builder.withEncryption(encryption);
    }
    try (ParquetWriter<Group> writer = builder.build()) {
      for (int i = 0; i < count; i++) {
        Group row = factory.newGroup().append("plain", i).append("footer", i * 2);
        row.addGroup("nested").append("secret", "row-" + i);
        writer.write(row);
      }
    }
    return file;
  }
}
