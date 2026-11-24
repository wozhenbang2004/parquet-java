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
package org.apache.parquet.cli.commands;

import static org.apache.parquet.bytes.BytesUtils.readIntLittleEndian;
import static org.apache.parquet.hadoop.ParquetFileWriter.EFMAGIC;
import static org.apache.parquet.hadoop.ParquetFileWriter.MAGIC;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.apache.parquet.Preconditions;
import org.apache.parquet.cli.BaseCommand;
import org.apache.parquet.format.AesGcmCtrV1;
import org.apache.parquet.format.AesGcmV1;
import org.apache.parquet.format.ColumnChunk;
import org.apache.parquet.format.ColumnCryptoMetaData;
import org.apache.parquet.format.EncryptionAlgorithm;
import org.apache.parquet.format.EncryptionWithColumnKey;
import org.apache.parquet.format.FileCryptoMetaData;
import org.apache.parquet.format.FileMetaData;
import org.apache.parquet.format.RowGroup;
import org.apache.parquet.format.Util;
import org.apache.parquet.hadoop.util.HadoopInputFile;
import org.apache.parquet.io.InputFile;
import org.apache.parquet.io.SeekableInputStream;
import org.slf4j.Logger;

@Parameters(commandDescription = "Print encryption metadata visible without decryption keys")
public class EncryptionInfoCommand extends BaseCommand {

  @Parameter(description = "<parquet path>", required = true)
  List<String> targets;

  @Parameter(names = "--show-key-metadata", description = "Print key retrieval metadata as hexadecimal")
  boolean showKeyMetadata;

  @Parameter(names = "--show-aad", description = "Print stored AAD fields as hexadecimal")
  boolean showAad;

  public EncryptionInfoCommand(Logger console) {
    super(console);
  }

  @Override
  public int run() throws IOException {
    Preconditions.checkArgument(targets.size() == 1, "Exactly one Parquet file is required.");
    InputFile file = HadoopInputFile.fromPath(qualifiedPath(targets.get(0)), getConf());
    long length = file.getLength();
    Preconditions.checkArgument(length >= 12, "Not a Parquet file: length is too small.");

    try (SeekableInputStream stream = file.newStream()) {
      long lengthIndex = length - MAGIC.length - Integer.BYTES;
      stream.seek(lengthIndex);
      long footerLength = readIntLittleEndian(stream) & 0xFFFFFFFFL;
      byte[] magic = new byte[MAGIC.length];
      stream.readFully(magic);
      boolean encryptedFooter = Arrays.equals(EFMAGIC, magic);
      Preconditions.checkArgument(
          encryptedFooter || Arrays.equals(MAGIC, magic), "Not a Parquet file: invalid tail magic.");
      Preconditions.checkArgument(footerLength <= Integer.MAX_VALUE, "Parquet footer is too large to read.");
      long footerIndex = lengthIndex - footerLength;
      Preconditions.checkArgument(
          footerIndex >= MAGIC.length && footerIndex < lengthIndex,
          "Invalid Parquet footer length: %s.",
          footerLength);
      stream.seek(footerIndex);
      byte[] footer = new byte[(int) footerLength];
      stream.readFully(footer);
      ByteArrayInputStream input = new ByteArrayInputStream(footer);

      if (encryptedFooter) {
        // FileCryptoMetaData precedes the encrypted footer and is itself plaintext.
        FileCryptoMetaData metadata = Util.readFileCryptoMetaData(input);
        console.info("Footer: encrypted");
        printAlgorithm(metadata.getEncryption_algorithm());
        printBinary("Footer key metadata", metadata.getKey_metadata(), showKeyMetadata);
        console.info("Column encryption: unavailable (encrypted footer)");
        console.info("All column chunks use footer key: unknown (encrypted footer)");
      } else {
        FileMetaData metadata = Util.readFileMetaData(input);
        console.info("Footer: plaintext");
        if (metadata.isSetEncryption_algorithm()) {
          printAlgorithm(metadata.getEncryption_algorithm());
          printBinary("Footer key metadata", metadata.getFooter_signing_key_metadata(), showKeyMetadata);
        } else {
          console.info("Encryption algorithm: none");
        }
        printColumns(metadata);
      }
    }
    return 0;
  }

  private void printAlgorithm(EncryptionAlgorithm algorithm) {
    Preconditions.checkArgument(algorithm != null, "Missing encryption algorithm.");
    byte[] prefix;
    byte[] fileUnique;
    boolean supplyPrefix;
    if (algorithm.isSetAES_GCM_V1()) {
      console.info("Encryption algorithm: AES_GCM_V1");
      AesGcmV1 parameters = algorithm.getAES_GCM_V1();
      prefix = parameters.getAad_prefix();
      fileUnique = parameters.getAad_file_unique();
      supplyPrefix = parameters.isSupply_aad_prefix();
    } else if (algorithm.isSetAES_GCM_CTR_V1()) {
      console.info("Encryption algorithm: AES_GCM_CTR_V1");
      AesGcmCtrV1 parameters = algorithm.getAES_GCM_CTR_V1();
      prefix = parameters.getAad_prefix();
      fileUnique = parameters.getAad_file_unique();
      supplyPrefix = parameters.isSupply_aad_prefix();
    } else {
      throw new IllegalArgumentException("Unsupported encryption algorithm: " + algorithm.getSetField());
    }
    printBinary("AAD prefix", prefix, showAad);
    printBinary("AAD file identifier", fileUnique, showAad);
    console.info("AAD prefix supplied by reader: {}", supplyPrefix);
    console.info("Authentication: not checked (no decryption keys)");
  }

  private void printColumns(FileMetaData metadata) {
    boolean allFooterKey = true;
    boolean hasColumns = false;
    int rowGroupIndex = 0;
    for (RowGroup rowGroup : metadata.getRow_groups()) {
      console.info("\nRow group {}:", rowGroupIndex++);
      for (ColumnChunk column : rowGroup.getColumns()) {
        hasColumns = true;
        ColumnCryptoMetaData crypto = column.getCrypto_metadata();
        if (crypto != null && crypto.isSetENCRYPTION_WITH_COLUMN_KEY()) {
          EncryptionWithColumnKey properties = crypto.getENCRYPTION_WITH_COLUMN_KEY();
          console.info("  {}: column key", String.join(".", properties.getPath_in_schema()));
          printBinary("    Key metadata", properties.getKey_metadata(), showKeyMetadata);
          allFooterKey = false;
        } else {
          Preconditions.checkArgument(
              column.isSetMeta_data(), "Missing column metadata in row group %s.", rowGroupIndex - 1);
          String path = String.join(".", column.getMeta_data().getPath_in_schema());
          if (crypto == null) {
            console.info("  {}: plaintext", path);
            allFooterKey = false;
          } else {
            Preconditions.checkArgument(
                crypto.isSetENCRYPTION_WITH_FOOTER_KEY(), "Unsupported column encryption for %s.", path);
            console.info("  {}: footer key", path);
          }
        }
      }
    }
    console.info(
        "All column chunks use footer key: {}",
        hasColumns ? Boolean.toString(allFooterKey) : "unknown (no columns)");
  }

  private void printBinary(String label, byte[] value, boolean showValue) {
    if (value == null) {
      console.info("{}: absent", label);
    } else if (showValue) {
      console.info("{}: {} bytes, hex={}", label, value.length, HexFormat.of().formatHex(value));
    } else {
      console.info("{}: present ({} bytes)", label, value.length);
    }
  }

  @Override
  public List<String> getExamples() {
    return List.of(
        "# Inspect encryption metadata without keys:",
        "sample.parquet",
        "# Include binary key metadata and stored AAD fields:",
        "sample.parquet --show-key-metadata --show-aad");
  }
}
