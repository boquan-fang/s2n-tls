#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

set -ex
source codebuild/bin/s2n_setup_env.sh


 # Install latest version of clang, clang++, and llvm-symbolizer. Needed for fuzzing.
if [[ "$TESTS" == "fuzz" || "$TESTS" == "ALL" || "$LATEST_CLANG" == "true" ]]; then
    mkdir -p "$LATEST_CLANG_INSTALL_DIR"||true
    codebuild/bin/install_clang.sh "$(mktemp -d)" "$LATEST_CLANG_INSTALL_DIR" "$OS_NAME" > /dev/null ;
fi

# Download and Install Openssl 1.1.1
if [[ ("$S2N_LIBCRYPTO" == "openssl-1.1.1") || ( "$TESTS" == "integrationv2" || "$TESTS" == "ALL" ) ]]; then
    if [[ ! -x "$OPENSSL_1_1_1_INSTALL_DIR/bin/openssl" ]]; then
      mkdir -p "$OPENSSL_1_1_1_INSTALL_DIR"||true
      codebuild/bin/install_openssl_1_1_1.sh "$(mktemp -d)" "$OPENSSL_1_1_1_INSTALL_DIR" "$OS_NAME" > /dev/null ;
    fi
fi

# Download and Install Openssl 3.0
if [[ "$S2N_LIBCRYPTO" == "openssl-3.0" && ! -d "$OPENSSL_3_0_INSTALL_DIR" ]]; then
    mkdir -p "$OPENSSL_3_0_INSTALL_DIR"
    codebuild/bin/install_openssl_3_0.sh "$(mktemp -d)" "$OPENSSL_3_0_INSTALL_DIR" "$OS_NAME" > /dev/null ;
fi

# Download and Install Openssl 3.0 FIPS
if [[ "$S2N_LIBCRYPTO" == "openssl-3.0-fips" && ! -d "$OPENSSL_3_FIPS_INSTALL_DIR" ]]; then
    mkdir -p "$OPENSSL_3_FIPS_INSTALL_DIR"
    codebuild/bin/install_openssl_3_0.sh "$(mktemp -d)" "$OPENSSL_3_FIPS_INSTALL_DIR" "$OS_NAME" fips > /dev/null ;
fi

# Download and Install Openssl 1.0.2
if [[ "$S2N_LIBCRYPTO" == "openssl-1.0.2" && ! -d "$OPENSSL_1_0_2_INSTALL_DIR" ]]; then
    mkdir -p "$OPENSSL_1_0_2_INSTALL_DIR"||true
    codebuild/bin/install_openssl_1_0_2.sh "$(mktemp -d)" "$OPENSSL_1_0_2_INSTALL_DIR" "$OS_NAME" > /dev/null ;
fi

# Download and Install the Openssl FIPS module and Openssl 1.0.2-fips
if [[ "$S2N_LIBCRYPTO" == "openssl-1.0.2-fips" ]] && [[ ! -d "$OPENSSL_1_0_2_FIPS_INSTALL_DIR" ]]; then
    codebuild/bin/install_openssl_1_0_2_fips.sh "$(mktemp -d)" "$OPENSSL_1_0_2_FIPS_INSTALL_DIR" "$OS_NAME" ; fi

# Download and Install LibreSSL
if [[ "$S2N_LIBCRYPTO" == "libressl" && ! -d "$LIBRESSL_INSTALL_DIR" ]]; then
    mkdir -p "$LIBRESSL_INSTALL_DIR"||true
    codebuild/bin/install_libressl.sh "$(mktemp -d)" "$LIBRESSL_INSTALL_DIR" > /dev/null ;
fi

# Download and Install BoringSSL
if [[ "$S2N_LIBCRYPTO" == "boringssl" && ! -d "$BORINGSSL_INSTALL_DIR" ]]; then
    codebuild/bin/install_boringssl.sh "$(mktemp -d)" "$BORINGSSL_INSTALL_DIR" > /dev/null ;
fi

# Download and Install AWS-LC
if [[ "$S2N_LIBCRYPTO" == "awslc" && ! -d "$AWSLC_INSTALL_DIR" ]]; then
    codebuild/bin/install_awslc.sh "$(mktemp -d)" "$AWSLC_INSTALL_DIR" > /dev/null ;
fi

if [[ "$S2N_LIBCRYPTO" == "awslc-fips-2022" && ! -d "$AWSLC_FIPS_2022_INSTALL_DIR" ]]; then
    codebuild/bin/install_awslc.sh "$(mktemp -d)" "$AWSLC_FIPS_2022_INSTALL_DIR" "2022" > /dev/null ;
fi
if [[ "$S2N_LIBCRYPTO" == "awslc-fips-2024" && ! -d "$AWSLC_FIPS_2024_INSTALL_DIR" ]]; then
    codebuild/bin/install_awslc_fips_2024.sh "$(mktemp -d)" "$AWSLC_FIPS_2024_INSTALL_DIR" "2024" > /dev/null ;
fi

if [[ "$TESTS" == "integrationv2" || "$TESTS" == "ALL" ]]; then
    # Install tox
    if [[ "$DISTRO" == "ubuntu" ]]; then
        if [[ ! -x `python3.9 -m tox --version` ]]; then
            python3.9 -m pip install tox
        fi
    else
        if [[ ! -x `which tox` ]]; then
            case "$DISTRO" in
            "amazon linux")
                yum install -y python3-pip
                python3 -m pip install --user tox ;;
            "apple")
                brew install python@3
                python3 -m pip install --user tox ;;
            *)
                echo "Unkown platform $DISTRO trying to install tox on $OS_NAME $ARCH"
                exit 1
                ;;
            esac
        fi
    fi

    if [[ ! -x "$GNUTLS37_INSTALL_DIR/bin/gnutls-cli" ]]; then
      # Download and Install GnuTLS for integration tests
      mkdir -p "$GNUTLS37_INSTALL_DIR"||true
      codebuild/bin/install_gnutls37.sh "$(mktemp -d)" "$GNUTLS37_INSTALL_DIR" > /dev/null ;
    fi

    if [[ ! -x "$OQS_OPENSSL_1_1_1_INSTALL_DIR/bin/openssl" ]]; then
      # Download and Install OQS OpenSSL for integration tests
      mkdir -p "$OQS_OPENSSL_1_1_1_INSTALL_DIR" ||true
      codebuild/bin/install_oqs_openssl_1_1_1.sh "$(mktemp -d)" "$OQS_OPENSSL_1_1_1_INSTALL_DIR" "$OS_NAME" | head -50
    fi

    if [[ "$DISTRO" == "ubuntu" ]]; then
        # Install SSLyze for all Integration Tests on Ubuntu.
        # There is a nassl dependancy issue preventing this from working on on AL2 ARM (others?).
        if [[ "$S2N_NO_SSLYZE" != "true" ]]; then
            codebuild/bin/install_sslyze.sh
        fi

        if [[ ! -x "$APACHE2_INSTALL_DIR/apache2.conf" ]]; then
            codebuild/bin/install_apache2.sh codebuild/bin/apache2 "$APACHE2_INSTALL_DIR"
        fi
    fi
fi

# Install SAW, Z3, and Yices for formal verification
if [[ "$SAW" == "true" || "$TESTS" == "ALL" ]]; then
    mkdir -p "$SAW_INSTALL_DIR"||true
    codebuild/bin/install_saw.sh "$(mktemp -d)" "$SAW_INSTALL_DIR" > /dev/null ;

    mkdir -p "$Z3_INSTALL_DIR"||true
    codebuild/bin/install_z3_yices.sh "$(mktemp -d)" "$Z3_INSTALL_DIR" > /dev/null ;
fi

if [[ ! -x `which cmake` ]]; then
    case "$DISTRO" in
    "ubuntu")
        apt-get -y install cmake
        ;;
    "amazon linux")
        yum install -y cmake3
        update-alternatives --install /usr/bin/cmake cmake /usr/bin/cmake3 30
        ;;
    "apple")
        brew install cmake
        ;;
    *)
        echo "Unknown platform for cmake."
        ;;
    esac
fi
