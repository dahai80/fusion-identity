# Homebrew formula for fusion-identity — source of truth lives in the
# fusion-identity repo (packaging/homebrew/) and is copied verbatim into
# dahai80/homebrew-fusion-mlx on each release with the real sha256s.
#
# The install ships a pre-built relocatable venv (built by
# scripts/package-venv.sh, smoke-tested for relocation in CI): the formula
# only has to point pyvenv.cfg and the script shebangs at Homebrew's
# python@3.12 and expose the console script on PATH.

class FusionIdentity < Formula
    desc "Fusion tenant-identity service — JWT issuer + tenant registry"
    homepage "https://github.com/dahai80/fusion-identity"
    version "0.2.46"
    license "MIT"

    base_url = "https://github.com/dahai80/fusion-identity/releases/download/v#{version}"

    on_macos do
        on_arm do
            url "#{base_url}/fusion-identity-venv-#{version}-darwin-arm64.tar.gz"
            sha256 "2d05de01d9e75fba73face751a443b25d2c6a40028121080f6563f9365ffd789"
        end
        on_intel do
            url "#{base_url}/fusion-identity-venv-#{version}-darwin-x64.tar.gz"
            sha256 "7a13b357d8dffdbb8cf783c68872d27524fee9f70059bbf917592ab45c777727"
        end
    end
    on_linux do
        on_arm do
            url "#{base_url}/fusion-identity-venv-#{version}-linux-arm64.tar.gz"
            sha256 "7548423377060c765472e0dc50d9ad9b630620ed36258ba5c004cbbc0add7535"
        end
        on_intel do
            url "#{base_url}/fusion-identity-venv-#{version}-linux-x64.tar.gz"
            sha256 "7ab7136bcd8732d04775fe06e33b8ecbe53f3f400c9247a606615ac41c447a25"
        end
    end

    # The copied interpreter still resolves its stdlib through pyvenv.cfg's
    # home, which the formula rewrites below to the Homebrew python.
    depends_on "python@3.12"

    def install
        python3 = Formula["python@3.12"]
        # Homebrew may or may not preserve the tarball's leading `venv/`
        # component depending on version; normalize both layouts to
        # libexec/venv.
        if File.directory?("venv")
            libexec.install "venv"
        else
            (libexec/"venv").install Dir["*"]
        end
        venv = libexec/"venv"

        cfg = venv/"pyvenv.cfg"
        # Python 3.12 pyvenv.cfg carries no base-* keys — relocation only
        # needs `home` (stdlib prefix) and `executable` (informational).
        # home must be the dir of the REAL framework binary, so resolve the
        # opt_bin symlink first.
        py = Pathname.new(File.realpath(python3.opt_bin/"python3.12"))
        inreplace cfg, /^home = .*$/, "home = #{py.parent}"
        inreplace cfg, /^executable = .*$/, "executable = #{py}"

        # Console scripts carry the build machine's absolute venv path in
        # their shebang; repoint every script at the relocated interpreter.
        Dir[venv/"bin/*"].each do |f|
            next unless File.file?(f) && File.executable?(f)
            next unless File.open(f, "rb") { |io| io.read(2) } == "#!"
            inreplace f, /^#!.*$/, "#!#{venv}/bin/python"
        end

        bin.install_symlink venv/"bin/fusion-identity"
    end

    def caveats
        <<~EOS
            Required env (fail-closed — the service refuses to start without them):
              export FUSION_IDENTITY_JWT_KEY="$(openssl rand -hex 32)"
              export FUSION_IDENTITY_SERVICE_TOKEN="$(openssl rand -hex 24)"
              export FUSION_BOOTSTRAP_ADMIN_USER=admin
              export FUSION_BOOTSTRAP_ADMIN_PASS=adminpass

            Full env table: https://github.com/dahai80/fusion-identity#configuration
        EOS
    end

    test do
        assert_match version.to_s, shell_output("#{bin}/fusion-identity --version")
    end
end
