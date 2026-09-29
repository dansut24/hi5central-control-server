export const expandedSoftwareCatalogue = [
  {
    "sourceKey": "nodejs",
    "displayName": "Node.js",
    "canonicalName": "Node.js",
    "publisher": "OpenJS Foundation",
    "sourceType": "vendor_json",
    "sourceUrl": "https://nodejs.org/dist/index.json",
    "parserConfig": {
      "versionPath": "0.version",
      "releaseDatePath": "0.date"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 30
  },
  {
    "sourceKey": "python",
    "displayName": "Python",
    "canonicalName": "Python",
    "publisher": "Python Software Foundation",
    "sourceType": "python_releases",
    "sourceUrl": "https://www.python.org/api/v2/downloads/release/?is_published=true",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "eclipse_temurin",
    "displayName": "Eclipse Temurin (Java)",
    "canonicalName": "Eclipse Temurin JDK",
    "publisher": "Eclipse Adoptium",
    "sourceType": "adoptium",
    "sourceUrl": "https://api.adoptium.net/v3/info/available_releases",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "vlc_media_player",
    "displayName": "VLC media player",
    "canonicalName": "VLC media player",
    "publisher": "VideoLAN",
    "sourceType": "vendor_text",
    "sourceUrl": "https://get.videolan.org/vlc/last/win64/",
    "adapter": "vlc_directory",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "VideoLAN.VLC",
    "nvdVendor": "videolan",
    "nvdProduct": "vlc_media_player",
    "pollMinutes": 60
  },
  {
    "sourceKey": "signal_desktop",
    "displayName": "Signal Desktop",
    "canonicalName": "Signal Desktop",
    "publisher": "Signal Messenger, LLC",
    "namePattern": "Signal",
    "publisherPattern": "Signal Messenger, LLC",
    "verificationConfig": {
      "method": "uninstall_registry",
      "displayNameContains": "Signal",
      "publisherContains": "Signal Messenger, LLC"
    },
    "sourceType": "vendor_text",
    "sourceUrl": "https://updates.signal.org/desktop/latest.yml",
    "adapter": "signal_yaml",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 30
  },
  {
    "sourceKey": "go_golang",
    "displayName": "Go (Golang)",
    "canonicalName": "Go Programming Language amd64",
    "publisher": "https://go.dev",
    "sourceType": "vendor_json",
    "sourceUrl": "https://go.dev/dl/?mode=json",
    "parserConfig": {
      "versionPath": "0.version"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "jenkins",
    "displayName": "Jenkins",
    "canonicalName": "Jenkins",
    "publisher": "Jenkins project",
    "sourceType": "vendor_text",
    "sourceUrl": "https://updates.jenkins.io/update-center.json",
    "adapter": "jenkins_jsonp",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "gradle",
    "displayName": "Gradle",
    "canonicalName": "Gradle",
    "publisher": "Gradle Inc.",
    "sourceType": "vendor_json",
    "sourceUrl": "https://services.gradle.org/versions/current",
    "parserConfig": {
      "versionPath": "version"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "hashicorp_terraform",
    "displayName": "HashiCorp Terraform",
    "canonicalName": "Terraform",
    "publisher": "HashiCorp",
    "sourceType": "hashicorp_releases",
    "sourceUrl": "https://releases.hashicorp.com/terraform/index.json",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "hashicorp_vault",
    "displayName": "HashiCorp Vault",
    "canonicalName": "Vault",
    "publisher": "HashiCorp",
    "sourceType": "hashicorp_releases",
    "sourceUrl": "https://releases.hashicorp.com/vault/index.json",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "hashicorp_consul",
    "displayName": "HashiCorp Consul",
    "canonicalName": "Consul",
    "publisher": "HashiCorp",
    "sourceType": "hashicorp_releases",
    "sourceUrl": "https://releases.hashicorp.com/consul/index.json",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "hashicorp_packer",
    "displayName": "HashiCorp Packer",
    "canonicalName": "Packer",
    "publisher": "HashiCorp",
    "sourceType": "hashicorp_releases",
    "sourceUrl": "https://releases.hashicorp.com/packer/index.json",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "hashicorp_vagrant",
    "displayName": "HashiCorp Vagrant",
    "canonicalName": "Vagrant",
    "publisher": "HashiCorp",
    "sourceType": "hashicorp_releases",
    "sourceUrl": "https://releases.hashicorp.com/vagrant/index.json",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "hashicorp_nomad",
    "displayName": "HashiCorp Nomad",
    "canonicalName": "Nomad",
    "publisher": "HashiCorp",
    "sourceType": "hashicorp_releases",
    "sourceUrl": "https://releases.hashicorp.com/nomad/index.json",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "hashicorp_boundary",
    "displayName": "HashiCorp Boundary",
    "canonicalName": "Boundary",
    "publisher": "HashiCorp",
    "sourceType": "hashicorp_releases",
    "sourceUrl": "https://releases.hashicorp.com/boundary/index.json",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "hashicorp_waypoint",
    "displayName": "HashiCorp Waypoint",
    "canonicalName": "Waypoint",
    "publisher": "HashiCorp",
    "sourceType": "hashicorp_releases",
    "sourceUrl": "https://releases.hashicorp.com/waypoint/index.json",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "jetbrains_intellij_idea_ultimate",
    "displayName": "IntelliJ IDEA Ultimate",
    "canonicalName": "IntelliJ IDEA Ultimate",
    "publisher": "JetBrains s.r.o.",
    "sourceType": "vendor_json",
    "sourceUrl": "https://data.services.jetbrains.com/products?code=IIU&latest=true",
    "parserConfig": {
      "versionPath": "0.releases.0.version",
      "releaseDatePath": "0.releases.0.date",
      "installerUrlPath": "0.releases.0.downloads.windows.link"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "jetbrains_intellij_idea_community",
    "displayName": "IntelliJ IDEA Community",
    "canonicalName": "IntelliJ IDEA Community",
    "publisher": "JetBrains s.r.o.",
    "sourceType": "vendor_json",
    "sourceUrl": "https://data.services.jetbrains.com/products?code=IIC&latest=true",
    "parserConfig": {
      "versionPath": "0.releases.0.version",
      "releaseDatePath": "0.releases.0.date",
      "installerUrlPath": "0.releases.0.downloads.windows.link"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "jetbrains_pycharm_professional",
    "displayName": "PyCharm Professional",
    "canonicalName": "PyCharm Professional",
    "publisher": "JetBrains s.r.o.",
    "sourceType": "vendor_json",
    "sourceUrl": "https://data.services.jetbrains.com/products?code=PCP&latest=true",
    "parserConfig": {
      "versionPath": "0.releases.0.version",
      "releaseDatePath": "0.releases.0.date",
      "installerUrlPath": "0.releases.0.downloads.windows.link"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "jetbrains_pycharm_community",
    "displayName": "PyCharm Community",
    "canonicalName": "PyCharm Community",
    "publisher": "JetBrains s.r.o.",
    "sourceType": "vendor_json",
    "sourceUrl": "https://data.services.jetbrains.com/products?code=PCC&latest=true",
    "parserConfig": {
      "versionPath": "0.releases.0.version",
      "releaseDatePath": "0.releases.0.date",
      "installerUrlPath": "0.releases.0.downloads.windows.link"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "jetbrains_webstorm",
    "displayName": "WebStorm",
    "canonicalName": "WebStorm",
    "publisher": "JetBrains s.r.o.",
    "sourceType": "vendor_json",
    "sourceUrl": "https://data.services.jetbrains.com/products?code=WS&latest=true",
    "parserConfig": {
      "versionPath": "0.releases.0.version",
      "releaseDatePath": "0.releases.0.date",
      "installerUrlPath": "0.releases.0.downloads.windows.link"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "jetbrains_phpstorm",
    "displayName": "PhpStorm",
    "canonicalName": "PhpStorm",
    "publisher": "JetBrains s.r.o.",
    "sourceType": "vendor_json",
    "sourceUrl": "https://data.services.jetbrains.com/products?code=PS&latest=true",
    "parserConfig": {
      "versionPath": "0.releases.0.version",
      "releaseDatePath": "0.releases.0.date",
      "installerUrlPath": "0.releases.0.downloads.windows.link"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "jetbrains_rider",
    "displayName": "Rider",
    "canonicalName": "Rider",
    "publisher": "JetBrains s.r.o.",
    "sourceType": "vendor_json",
    "sourceUrl": "https://data.services.jetbrains.com/products?code=RD&latest=true",
    "parserConfig": {
      "versionPath": "0.releases.0.version",
      "releaseDatePath": "0.releases.0.date",
      "installerUrlPath": "0.releases.0.downloads.windows.link"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "jetbrains_datagrip",
    "displayName": "DataGrip",
    "canonicalName": "DataGrip",
    "publisher": "JetBrains s.r.o.",
    "sourceType": "vendor_json",
    "sourceUrl": "https://data.services.jetbrains.com/products?code=DG&latest=true",
    "parserConfig": {
      "versionPath": "0.releases.0.version",
      "releaseDatePath": "0.releases.0.date",
      "installerUrlPath": "0.releases.0.downloads.windows.link"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "jetbrains_clion",
    "displayName": "CLion",
    "canonicalName": "CLion",
    "publisher": "JetBrains s.r.o.",
    "sourceType": "vendor_json",
    "sourceUrl": "https://data.services.jetbrains.com/products?code=CL&latest=true",
    "parserConfig": {
      "versionPath": "0.releases.0.version",
      "releaseDatePath": "0.releases.0.date",
      "installerUrlPath": "0.releases.0.downloads.windows.link"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "jetbrains_goland",
    "displayName": "GoLand",
    "canonicalName": "GoLand",
    "publisher": "JetBrains s.r.o.",
    "sourceType": "vendor_json",
    "sourceUrl": "https://data.services.jetbrains.com/products?code=GO&latest=true",
    "parserConfig": {
      "versionPath": "0.releases.0.version",
      "releaseDatePath": "0.releases.0.date",
      "installerUrlPath": "0.releases.0.downloads.windows.link"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "jetbrains_rubymine",
    "displayName": "RubyMine",
    "canonicalName": "RubyMine",
    "publisher": "JetBrains s.r.o.",
    "sourceType": "vendor_json",
    "sourceUrl": "https://data.services.jetbrains.com/products?code=RM&latest=true",
    "parserConfig": {
      "versionPath": "0.releases.0.version",
      "releaseDatePath": "0.releases.0.date",
      "installerUrlPath": "0.releases.0.downloads.windows.link"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "jetbrains_appcode",
    "displayName": "AppCode",
    "canonicalName": "AppCode",
    "publisher": "JetBrains s.r.o.",
    "sourceType": "vendor_json",
    "sourceUrl": "https://data.services.jetbrains.com/products?code=AC&latest=true",
    "parserConfig": {
      "versionPath": "0.releases.0.version",
      "releaseDatePath": "0.releases.0.date",
      "installerUrlPath": "0.releases.0.downloads.windows.link"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "jetbrains_jetbrains_toolbox_app",
    "displayName": "JetBrains Toolbox App",
    "canonicalName": "JetBrains Toolbox App",
    "publisher": "JetBrains s.r.o.",
    "sourceType": "vendor_json",
    "sourceUrl": "https://data.services.jetbrains.com/products?code=TBA&latest=true",
    "parserConfig": {
      "versionPath": "0.releases.0.version",
      "releaseDatePath": "0.releases.0.date",
      "installerUrlPath": "0.releases.0.downloads.windows.link"
    },
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60
  },
  {
    "sourceKey": "gh_brave_brave_browser",
    "displayName": "Brave Browser",
    "canonicalName": "Brave Browser",
    "sourceType": "github_releases",
    "repository": "brave/brave-browser",
    "namePattern": "Brave",
    "publisherPattern": "Brave Software",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "Brave.Brave",
    "versionNormalization": {
      "strategy": "strip_leading_numeric_segments",
      "installedSegmentsToStrip": 1,
      "providerSegmentsToStrip": 1,
      "expectedRemainingSegments": 3
    },
    "qualificationState": "deployment_candidate",
    "qualificationNotes": "Brave Windows/WinGet versions carry a Chromium-major prefix (for example 153.1.95.104) while upstream/NVD use the Brave product version (1.95.104). Comparisons normalize the installed/provider version by stripping one leading numeric segment.",
    "nvdVendor": "brave",
    "nvdProduct": "browser",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_vscodium_vscodium",
    "displayName": "VSCodium",
    "canonicalName": "VSCodium",
    "sourceType": "github_releases",
    "repository": "VSCodium/vscodium",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_qutebrowser_qutebrowser",
    "displayName": "qutebrowser",
    "canonicalName": "qutebrowser",
    "sourceType": "github_releases",
    "repository": "qutebrowser/qutebrowser",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_waterfoxco_waterfox",
    "displayName": "Waterfox",
    "canonicalName": "Waterfox",
    "sourceType": "github_releases",
    "repository": "WaterfoxCo/Waterfox",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_notepad_plus_plus_notepad_plus_plus",
    "displayName": "Notepad++",
    "canonicalName": "Notepad++",
    "sourceType": "github_releases",
    "repository": "notepad-plus-plus/notepad-plus-plus",
    "deploymentMode": "winget_preferred",
    "pollMinutes": 60,
    "enabled": true,
    "wingetPackageId": "Notepad++.Notepad++",
    "nvdVendor": "notepad-plus-plus",
    "nvdProduct": "notepad++"
  },
  {
    "sourceKey": "gh_vim_vim",
    "displayName": "Vim",
    "canonicalName": "Vim",
    "sourceType": "github_releases",
    "repository": "vim/vim",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": false
  },
  {
    "sourceKey": "gh_neovim_neovim",
    "displayName": "Neovim",
    "canonicalName": "Neovim",
    "sourceType": "github_releases",
    "repository": "neovim/neovim",
    "deploymentMode": "winget_preferred",
    "pollMinutes": 60,
    "enabled": true,
    "wingetPackageId": "Neovim.Neovim",
    "nvdVendor": "neovim",
    "nvdProduct": "neovim"
  },
  {
    "sourceKey": "gh_zed_industries_zed",
    "displayName": "Zed",
    "canonicalName": "Zed",
    "sourceType": "github_releases",
    "repository": "zed-industries/zed",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_lapce_lapce",
    "displayName": "Lapce",
    "canonicalName": "Lapce",
    "sourceType": "github_releases",
    "repository": "lapce/lapce",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_helix_editor_helix",
    "displayName": "Helix",
    "canonicalName": "Helix",
    "sourceType": "github_releases",
    "repository": "helix-editor/helix",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_git_for_windows_git",
    "displayName": "Git for Windows",
    "canonicalName": "Git for Windows",
    "namePattern": "Git",
    "publisherPattern": "The Git Development Community",
    "verificationConfig": {
      "method": "uninstall_registry",
      "displayNameContains": "Git",
      "publisherContains": "The Git Development Community",
      "versionTransform": "git_windows_registry"
    },
    "sourceType": "github_releases",
    "repository": "git-for-windows/git",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_desktop_desktop",
    "displayName": "GitHub Desktop",
    "canonicalName": "GitHub Desktop",
    "sourceType": "github_releases",
    "repository": "desktop/desktop",
    "namePattern": "GitHub Desktop",
    "publisherPattern": "GitHub",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "GitHub.GitHubDesktop",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_microsoft_terminal",
    "displayName": "Windows Terminal",
    "canonicalName": "Windows Terminal",
    "sourceType": "github_releases",
    "repository": "microsoft/terminal",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_vercel_hyper",
    "displayName": "Hyper",
    "canonicalName": "Hyper",
    "sourceType": "github_releases",
    "repository": "vercel/hyper",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_alacritty_alacritty",
    "displayName": "Alacritty",
    "canonicalName": "Alacritty",
    "sourceType": "github_releases",
    "repository": "alacritty/alacritty",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_wez_wezterm",
    "displayName": "WezTerm",
    "canonicalName": "WezTerm",
    "sourceType": "github_releases",
    "repository": "wez/wezterm",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_eugeny_tabby",
    "displayName": "Tabby",
    "canonicalName": "Tabby",
    "sourceType": "github_releases",
    "repository": "Eugeny/tabby",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_maximus5_conemu",
    "displayName": "ConEmu",
    "canonicalName": "ConEmu",
    "sourceType": "github_releases",
    "repository": "Maximus5/ConEmu",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_docker_compose",
    "displayName": "Docker Compose",
    "canonicalName": "Docker Compose",
    "sourceType": "github_releases",
    "repository": "docker/compose",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_helm_helm",
    "displayName": "Helm",
    "canonicalName": "Helm",
    "sourceType": "github_releases",
    "repository": "helm/helm",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_kubernetes_kubernetes",
    "displayName": "Kubernetes (kubectl)",
    "canonicalName": "Kubernetes (kubectl)",
    "sourceType": "github_releases",
    "repository": "kubernetes/kubernetes",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_kubernetes_minikube",
    "displayName": "Minikube",
    "canonicalName": "Minikube",
    "sourceType": "github_releases",
    "repository": "kubernetes/minikube",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_derailed_k9s",
    "displayName": "k9s",
    "canonicalName": "k9s",
    "sourceType": "github_releases",
    "repository": "derailed/k9s",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_lensapp_lens",
    "displayName": "Lens",
    "canonicalName": "Lens",
    "sourceType": "github_releases",
    "repository": "lensapp/lens",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_rancher_sandbox_rancher_desktop",
    "displayName": "Rancher Desktop",
    "canonicalName": "Rancher Desktop",
    "sourceType": "github_releases",
    "repository": "rancher-sandbox/rancher-desktop",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_containers_podman_desktop",
    "displayName": "Podman Desktop",
    "canonicalName": "Podman Desktop",
    "sourceType": "github_releases",
    "repository": "containers/podman-desktop",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_containers_podman",
    "displayName": "Podman",
    "canonicalName": "Podman",
    "sourceType": "github_releases",
    "repository": "containers/podman",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_aws_aws_cli",
    "displayName": "AWS CLI",
    "canonicalName": "AWS CLI",
    "sourceType": "github_releases",
    "repository": "aws/aws-cli",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": false
  },
  {
    "sourceKey": "gh_azure_azure_cli",
    "displayName": "Azure CLI",
    "canonicalName": "Azure CLI",
    "sourceType": "github_releases",
    "repository": "Azure/azure-cli",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_eksctl_io_eksctl",
    "displayName": "eksctl",
    "canonicalName": "eksctl",
    "sourceType": "github_releases",
    "repository": "eksctl-io/eksctl",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_gruntwork_io_terragrunt",
    "displayName": "Terragrunt",
    "canonicalName": "Terragrunt",
    "sourceType": "github_releases",
    "repository": "gruntwork-io/terragrunt",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_kubernetes_sigs_kind",
    "displayName": "kind",
    "canonicalName": "kind",
    "sourceType": "github_releases",
    "repository": "kubernetes-sigs/kind",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_googlecontainertools_skaffold",
    "displayName": "Skaffold",
    "canonicalName": "Skaffold",
    "sourceType": "github_releases",
    "repository": "GoogleContainerTools/skaffold",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_argoproj_argo_cd",
    "displayName": "Argo CD",
    "canonicalName": "Argo CD",
    "sourceType": "github_releases",
    "repository": "argoproj/argo-cd",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_kubernetes_sigs_kustomize",
    "displayName": "Kustomize",
    "canonicalName": "Kustomize",
    "sourceType": "github_releases",
    "repository": "kubernetes-sigs/kustomize",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_yarnpkg_yarn",
    "displayName": "Yarn",
    "canonicalName": "Yarn",
    "sourceType": "github_releases",
    "repository": "yarnpkg/yarn",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_pnpm_pnpm",
    "displayName": "pnpm",
    "canonicalName": "pnpm",
    "sourceType": "github_releases",
    "repository": "pnpm/pnpm",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_rust_lang_rustup",
    "displayName": "rustup",
    "canonicalName": "rustup",
    "sourceType": "github_releases",
    "repository": "rust-lang/rustup",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": false
  },
  {
    "sourceKey": "gh_astral_sh_uv",
    "displayName": "uv (Python)",
    "canonicalName": "uv (Python)",
    "sourceType": "github_releases",
    "repository": "astral-sh/uv",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_burntsushi_ripgrep",
    "displayName": "ripgrep",
    "canonicalName": "ripgrep",
    "sourceType": "github_releases",
    "repository": "BurntSushi/ripgrep",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_junegunn_fzf",
    "displayName": "fzf",
    "canonicalName": "fzf",
    "sourceType": "github_releases",
    "repository": "junegunn/fzf",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_sharkdp_bat",
    "displayName": "bat",
    "canonicalName": "bat",
    "sourceType": "github_releases",
    "repository": "sharkdp/bat",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_jqlang_jq",
    "displayName": "jq",
    "canonicalName": "jq",
    "sourceType": "github_releases",
    "repository": "jqlang/jq",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_mikefarah_yq",
    "displayName": "yq",
    "canonicalName": "yq",
    "sourceType": "github_releases",
    "repository": "mikefarah/yq",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_dbeaver_dbeaver",
    "displayName": "DBeaver",
    "canonicalName": "DBeaver",
    "sourceType": "github_releases",
    "repository": "dbeaver/dbeaver",
    "namePattern": "DBeaver",
    "publisherPattern": "DBeaver",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "DBeaver.DBeaver.Community",
    "nvdVendor": "dbeaver",
    "nvdProduct": "dbeaver",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_mongodb_js_compass",
    "displayName": "MongoDB Compass",
    "canonicalName": "MongoDB Compass",
    "sourceType": "github_releases",
    "repository": "mongodb-js/compass",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_redis_redisinsight",
    "displayName": "RedisInsight",
    "canonicalName": "RedisInsight",
    "sourceType": "github_releases",
    "repository": "redis/redisinsight",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_beekeeper_studio_beekeeper_studio",
    "displayName": "Beekeeper Studio",
    "canonicalName": "Beekeeper Studio",
    "sourceType": "github_releases",
    "repository": "beekeeper-studio/beekeeper-studio",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_grafana_grafana",
    "displayName": "Grafana",
    "canonicalName": "Grafana",
    "sourceType": "github_releases",
    "repository": "grafana/grafana",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_prometheus_prometheus",
    "displayName": "Prometheus",
    "canonicalName": "Prometheus",
    "sourceType": "github_releases",
    "repository": "prometheus/prometheus",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_postmanlabs_postman_app_support",
    "displayName": "Postman",
    "canonicalName": "Postman",
    "sourceType": "github_releases",
    "repository": "postmanlabs/postman-app-support",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": false
  },
  {
    "sourceKey": "gh_kong_insomnia",
    "displayName": "Insomnia",
    "canonicalName": "Insomnia",
    "sourceType": "github_releases",
    "repository": "Kong/insomnia",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_httpie_desktop",
    "displayName": "HTTPie Desktop",
    "canonicalName": "HTTPie Desktop",
    "sourceType": "github_releases",
    "repository": "httpie/desktop",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_usebruno_bruno",
    "displayName": "Bruno",
    "canonicalName": "Bruno",
    "sourceType": "github_releases",
    "repository": "usebruno/bruno",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_smartbear_soapui",
    "displayName": "SoapUI",
    "canonicalName": "SoapUI",
    "sourceType": "github_releases",
    "repository": "SmartBear/soapui",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_telegramdesktop_tdesktop",
    "displayName": "Telegram Desktop",
    "canonicalName": "Telegram Desktop",
    "sourceType": "github_releases",
    "repository": "telegramdesktop/tdesktop",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_element_hq_element_desktop",
    "displayName": "Element Desktop",
    "canonicalName": "Element Desktop",
    "sourceType": "github_releases",
    "repository": "element-hq/element-desktop",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_mattermost_desktop",
    "displayName": "Mattermost Desktop",
    "canonicalName": "Mattermost Desktop",
    "sourceType": "github_releases",
    "repository": "mattermost/desktop",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_zulip_zulip_desktop",
    "displayName": "Zulip Desktop",
    "canonicalName": "Zulip Desktop",
    "namePattern": "Zulip",
    "publisherPattern": "Kandra Labs",
    "verificationConfig": {
      "method": "uninstall_registry",
      "displayNameContains": "Zulip",
      "publisherContains": "Kandra Labs"
    },
    "sourceType": "github_releases",
    "repository": "zulip/zulip-desktop",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_ferdium_ferdium_app",
    "displayName": "Ferdium",
    "canonicalName": "Ferdium",
    "sourceType": "github_releases",
    "repository": "ferdium/ferdium-app",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_ramboxapp_community_edition",
    "displayName": "Rambox",
    "canonicalName": "Rambox",
    "sourceType": "github_releases",
    "repository": "ramboxapp/community-edition",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_session_foundation_session_desktop",
    "displayName": "Session Desktop",
    "canonicalName": "Session Desktop",
    "sourceType": "github_releases",
    "repository": "session-foundation/session-desktop",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_wireapp_wire_desktop",
    "displayName": "Wire Desktop",
    "canonicalName": "Wire Desktop",
    "sourceType": "github_releases",
    "repository": "wireapp/wire-desktop",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true,
    "releaseTagPattern": "windows/*"
  },
  {
    "sourceKey": "gh_jitsi_jitsi_meet_electron",
    "displayName": "Jitsi Meet Electron",
    "canonicalName": "Jitsi Meet Electron",
    "sourceType": "github_releases",
    "repository": "jitsi/jitsi-meet-electron",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_obsidianmd_obsidian_releases",
    "displayName": "Obsidian",
    "canonicalName": "Obsidian",
    "sourceType": "github_releases",
    "repository": "obsidianmd/obsidian-releases",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_laurent22_joplin",
    "displayName": "Joplin",
    "canonicalName": "Joplin",
    "sourceType": "github_releases",
    "repository": "laurent22/joplin",
    "namePattern": "Joplin",
    "publisherPattern": "Laurent Cozic",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "Joplin.Joplin",
    "nvdVendor": "joplin_project",
    "nvdProduct": "joplin",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_logseq_logseq",
    "displayName": "Logseq",
    "canonicalName": "Logseq",
    "sourceType": "github_releases",
    "repository": "logseq/logseq",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_standardnotes_app",
    "displayName": "Standard Notes",
    "canonicalName": "Standard Notes",
    "sourceType": "github_releases",
    "repository": "standardnotes/app",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_appflowy_io_appflowy",
    "displayName": "AppFlowy",
    "canonicalName": "AppFlowy",
    "sourceType": "github_releases",
    "repository": "AppFlowy-IO/AppFlowy",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_zadam_trilium",
    "displayName": "Trilium Notes",
    "canonicalName": "Trilium Notes",
    "sourceType": "github_releases",
    "repository": "zadam/trilium",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_siyuan_note_siyuan",
    "displayName": "SiYuan",
    "canonicalName": "SiYuan",
    "sourceType": "github_releases",
    "repository": "siyuan-note/siyuan",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_keepassxreboot_keepassxc",
    "displayName": "KeePassXC",
    "canonicalName": "KeePassXC",
    "sourceType": "github_releases",
    "repository": "keepassxreboot/keepassxc",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "KeePassXCTeam.KeePassXC",
    "nvdVendor": "keepassxc",
    "nvdProduct": "keepassxc",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_bitwarden_clients",
    "displayName": "Bitwarden Desktop",
    "canonicalName": "Bitwarden Desktop",
    "sourceType": "github_releases",
    "repository": "bitwarden/clients",
    "namePattern": "Bitwarden",
    "publisherPattern": "Bitwarden",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "Bitwarden.Bitwarden",
    "pollMinutes": 60,
    "enabled": true,
    "releaseTagPattern": "desktop-v*"
  },
  {
    "sourceKey": "gh_nationalsecurityagency_ghidra",
    "displayName": "Ghidra",
    "canonicalName": "Ghidra",
    "sourceType": "github_releases",
    "repository": "NationalSecurityAgency/ghidra",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_zaproxy_zaproxy",
    "displayName": "OWASP ZAP",
    "canonicalName": "OWASP ZAP",
    "sourceType": "github_releases",
    "repository": "zaproxy/zaproxy",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_rapid7_metasploit_framework",
    "displayName": "Metasploit Framework",
    "canonicalName": "Metasploit Framework",
    "sourceType": "github_releases",
    "repository": "rapid7/metasploit-framework",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": false
  },
  {
    "sourceKey": "gh_wazuh_wazuh",
    "displayName": "Wazuh",
    "canonicalName": "Wazuh",
    "sourceType": "vendor_text",
    "sourceUrl": "https://documentation.wazuh.com/current/installation-guide/packages-list.html",
    "adapter": "wazuh_windows_packages",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_rustdesk_rustdesk",
    "displayName": "RustDesk",
    "canonicalName": "RustDesk",
    "sourceType": "github_releases",
    "repository": "rustdesk/rustdesk",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_freerdp_remmina",
    "displayName": "Remmina",
    "canonicalName": "Remmina",
    "sourceType": "github_releases",
    "repository": "FreeRDP/Remmina",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_yubico_yubikey_manager_qt",
    "displayName": "YubiKey Manager (QT)",
    "canonicalName": "YubiKey Manager (QT)",
    "sourceType": "github_releases",
    "repository": "Yubico/yubikey-manager-qt",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_audacity_audacity",
    "displayName": "Audacity",
    "canonicalName": "Audacity",
    "sourceType": "github_releases",
    "repository": "audacity/audacity",
    "namePattern": "Audacity",
    "publisherPattern": "Audacity",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "Audacity.Audacity",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_obsproject_obs_studio",
    "displayName": "OBS Studio",
    "canonicalName": "OBS Studio",
    "sourceType": "github_releases",
    "repository": "obsproject/obs-studio",
    "namePattern": "OBS Studio",
    "publisherPattern": "OBS Project",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "OBSProject.OBSStudio",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_handbrake_handbrake",
    "displayName": "HandBrake",
    "canonicalName": "HandBrake",
    "sourceType": "github_releases",
    "repository": "HandBrake/HandBrake",
    "namePattern": "HandBrake",
    "publisherPattern": "HandBrake",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "HandBrake.HandBrake",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_mltframework_shotcut",
    "displayName": "Shotcut",
    "canonicalName": "Shotcut",
    "sourceType": "github_releases",
    "repository": "mltframework/shotcut",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_darktable_org_darktable",
    "displayName": "darktable",
    "canonicalName": "darktable",
    "sourceType": "github_releases",
    "repository": "darktable-org/darktable",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_beep6581_rawtherapee",
    "displayName": "RawTherapee",
    "canonicalName": "RawTherapee",
    "sourceType": "github_releases",
    "repository": "Beep6581/RawTherapee",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_natrongithub_natron",
    "displayName": "Natron",
    "canonicalName": "Natron",
    "sourceType": "github_releases",
    "repository": "NatronGitHub/Natron",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_synfig_synfig",
    "displayName": "Synfig Studio",
    "canonicalName": "Synfig Studio",
    "sourceType": "github_releases",
    "repository": "synfig/synfig",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_openshot_openshot_qt",
    "displayName": "OpenShot",
    "canonicalName": "OpenShot",
    "sourceType": "github_releases",
    "repository": "OpenShot/openshot-qt",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_mifi_lossless_cut",
    "displayName": "LosslessCut",
    "canonicalName": "LosslessCut",
    "sourceType": "github_releases",
    "repository": "mifi/lossless-cut",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_nickemanarin_screentogif",
    "displayName": "ScreenToGif",
    "canonicalName": "ScreenToGif",
    "sourceType": "github_releases",
    "repository": "NickeManarin/ScreenToGif",
    "namePattern": "ScreenToGif",
    "publisherPattern": "Nicke Manarin",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "NickeManarin.ScreenToGif",
    "nvdVendor": "screentogif",
    "nvdProduct": "screentogif",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_greenshot_greenshot",
    "displayName": "Greenshot",
    "canonicalName": "Greenshot",
    "sourceType": "github_releases",
    "repository": "greenshot/greenshot",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_sharex_sharex",
    "displayName": "ShareX",
    "canonicalName": "ShareX",
    "sourceType": "github_releases",
    "repository": "ShareX/ShareX",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "ShareX.ShareX",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_peazip_peazip",
    "displayName": "PeaZip",
    "canonicalName": "PeaZip",
    "sourceType": "github_releases",
    "repository": "peazip/PeaZip",
    "namePattern": "PeaZip",
    "publisherPattern": "Giorgio Tani",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "Giorgiotani.Peazip",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_files_community_files",
    "displayName": "Files (Windows)",
    "canonicalName": "Files (Windows)",
    "sourceType": "github_releases",
    "repository": "files-community/Files",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_balena_io_etcher",
    "displayName": "balenaEtcher",
    "canonicalName": "balenaEtcher",
    "sourceType": "github_releases",
    "repository": "balena-io/etcher",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_pbatard_rufus",
    "displayName": "Rufus",
    "canonicalName": "Rufus",
    "sourceType": "github_releases",
    "repository": "pbatard/rufus",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_ventoy_ventoy",
    "displayName": "Ventoy",
    "canonicalName": "Ventoy",
    "sourceType": "github_releases",
    "repository": "ventoy/Ventoy",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_winmerge_winmerge",
    "displayName": "WinMerge",
    "canonicalName": "WinMerge",
    "sourceType": "github_releases",
    "repository": "WinMerge/winmerge",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "WinMerge.WinMerge",
    "nvdVendor": "winmerge",
    "nvdProduct": "winmerge",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_windirstat_windirstat",
    "displayName": "WinDirStat",
    "canonicalName": "WinDirStat",
    "sourceType": "github_releases",
    "repository": "windirstat/windirstat",
    "namePattern": "WinDirStat",
    "publisherPattern": "WinDirStat",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "WinDirStat.WinDirStat",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_microsoft_powertoys",
    "displayName": "Microsoft PowerToys",
    "canonicalName": "Microsoft PowerToys",
    "namePattern": "PowerToys",
    "publisherPattern": "Microsoft",
    "sourceType": "github_releases",
    "repository": "microsoft/PowerToys",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "Microsoft.PowerToys",
    "nvdVendor": "microsoft",
    "nvdProduct": "powertoys",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_autohotkey_autohotkey",
    "displayName": "AutoHotkey",
    "canonicalName": "AutoHotkey",
    "sourceType": "github_releases",
    "repository": "AutoHotkey/AutoHotkey",
    "namePattern": "AutoHotkey",
    "publisherPattern": "AutoHotkey",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "AutoHotkey.AutoHotkey",
    "nvdVendor": "autohotkey",
    "nvdProduct": "autohotkey",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_espanso_espanso",
    "displayName": "Espanso",
    "canonicalName": "Espanso",
    "sourceType": "github_releases",
    "repository": "espanso/espanso",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_winsiderss_systeminformer",
    "displayName": "System Informer (Process Hacker)",
    "canonicalName": "System Informer (Process Hacker)",
    "sourceType": "github_releases",
    "repository": "winsiderss/systeminformer",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_librehardwaremonitor_librehardwaremonitor",
    "displayName": "LibreHardwareMonitor",
    "canonicalName": "LibreHardwareMonitor",
    "sourceType": "github_releases",
    "repository": "LibreHardwareMonitor/LibreHardwareMonitor",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_nicolargo_glances",
    "displayName": "Glances",
    "canonicalName": "Glances",
    "sourceType": "github_releases",
    "repository": "nicolargo/glances",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_netdata_netdata",
    "displayName": "Netdata",
    "canonicalName": "Netdata",
    "sourceType": "github_releases",
    "repository": "netdata/netdata",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_utmapp_utm",
    "displayName": "UTM",
    "canonicalName": "UTM",
    "sourceType": "github_releases",
    "repository": "utmapp/UTM",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_tigervnc_tigervnc",
    "displayName": "TigerVNC",
    "canonicalName": "TigerVNC",
    "sourceType": "github_releases",
    "repository": "TigerVNC/tigervnc",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_iterate_ch_cyberduck",
    "displayName": "Cyberduck",
    "canonicalName": "Cyberduck",
    "sourceType": "github_releases",
    "repository": "iterate-ch/cyberduck",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": false
  },
  {
    "sourceKey": "gh_onlyoffice_desktopeditors",
    "displayName": "OnlyOffice Desktop Editors",
    "canonicalName": "OnlyOffice Desktop Editors",
    "namePattern": "ONLYOFFICE",
    "publisherPattern": "Ascensio System SIA",
    "verificationConfig": {
      "method": "uninstall_registry",
      "displayNameContains": "ONLYOFFICE",
      "publisherContains": "Ascensio System SIA"
    },
    "sourceType": "github_releases",
    "repository": "ONLYOFFICE/DesktopEditors",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_zotero_zotero",
    "displayName": "Zotero",
    "canonicalName": "Zotero",
    "sourceType": "github_releases",
    "repository": "zotero/zotero",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": false
  },
  {
    "sourceKey": "gh_kovidgoyal_calibre",
    "displayName": "Calibre",
    "canonicalName": "Calibre",
    "sourceType": "github_releases",
    "repository": "kovidgoyal/calibre",
    "namePattern": "calibre",
    "publisherPattern": "Kovid Goyal",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "calibre.calibre",
    "nvdVendor": "calibre-ebook",
    "nvdProduct": "calibre",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_nextcloud_desktop",
    "displayName": "Nextcloud Desktop",
    "canonicalName": "Nextcloud Desktop",
    "sourceType": "vendor_text",
    "sourceUrl": "https://download.nextcloud.com/desktop/releases/Windows/",
    "adapter": "nextcloud_windows_index",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_syncthing_syncthing",
    "displayName": "Syncthing",
    "canonicalName": "Syncthing",
    "sourceType": "github_releases",
    "repository": "syncthing/syncthing",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_rclone_rclone",
    "displayName": "rclone",
    "canonicalName": "rclone",
    "sourceType": "github_releases",
    "repository": "rclone/rclone",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_duplicati_duplicati",
    "displayName": "Duplicati",
    "canonicalName": "Duplicati",
    "sourceType": "github_releases",
    "repository": "duplicati/duplicati",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_restic_restic",
    "displayName": "restic",
    "canonicalName": "restic",
    "sourceType": "github_releases",
    "repository": "restic/restic",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_kopia_kopia",
    "displayName": "Kopia",
    "canonicalName": "Kopia",
    "sourceType": "github_releases",
    "repository": "kopia/kopia",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_openvpn_openvpn_gui",
    "displayName": "OpenVPN GUI",
    "canonicalName": "OpenVPN GUI",
    "sourceType": "github_releases",
    "repository": "OpenVPN/openvpn-gui",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": false
  },
  {
    "sourceKey": "gh_caddyserver_caddy",
    "displayName": "Caddy",
    "canonicalName": "Caddy",
    "sourceType": "github_releases",
    "repository": "caddyserver/caddy",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_traefik_traefik",
    "displayName": "Traefik",
    "canonicalName": "Traefik",
    "sourceType": "github_releases",
    "repository": "traefik/traefik",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_minio_minio",
    "displayName": "MinIO",
    "canonicalName": "MinIO",
    "sourceType": "github_releases",
    "repository": "minio/minio",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_portainer_portainer",
    "displayName": "Portainer",
    "canonicalName": "Portainer",
    "sourceType": "github_releases",
    "repository": "portainer/portainer",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_denoland_deno",
    "displayName": "Deno",
    "canonicalName": "Deno",
    "sourceType": "github_releases",
    "repository": "denoland/deno",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_oven_sh_bun",
    "displayName": "Bun",
    "canonicalName": "Bun",
    "sourceType": "github_releases",
    "repository": "oven-sh/bun",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_freecad_freecad",
    "displayName": "FreeCAD",
    "canonicalName": "FreeCAD",
    "sourceType": "github_releases",
    "repository": "FreeCAD/FreeCAD",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_openscad_openscad",
    "displayName": "OpenSCAD",
    "canonicalName": "OpenSCAD",
    "sourceType": "github_releases",
    "repository": "openscad/openscad",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_librecad_librecad",
    "displayName": "LibreCAD",
    "canonicalName": "LibreCAD",
    "sourceType": "github_releases",
    "repository": "LibreCAD/LibreCAD",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_qgis_qgis",
    "displayName": "QGIS",
    "canonicalName": "QGIS",
    "sourceType": "github_releases",
    "repository": "qgis/QGIS",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_jgraph_drawio_desktop",
    "displayName": "draw.io Desktop",
    "canonicalName": "draw.io Desktop",
    "sourceType": "github_releases",
    "repository": "jgraph/drawio-desktop",
    "namePattern": "draw.io",
    "publisherPattern": "JGraph",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "JGraph.Draw",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_kitware_cmake",
    "displayName": "CMake",
    "canonicalName": "CMake",
    "sourceType": "github_releases",
    "repository": "Kitware/CMake",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_libretro_retroarch",
    "displayName": "RetroArch",
    "canonicalName": "RetroArch",
    "sourceType": "github_releases",
    "repository": "libretro/RetroArch",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_dolphin_emu_dolphin",
    "displayName": "Dolphin Emulator",
    "canonicalName": "Dolphin Emulator",
    "sourceType": "github_releases",
    "repository": "dolphin-emu/dolphin",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": false
  },
  {
    "sourceKey": "gh_pcsx2_pcsx2",
    "displayName": "PCSX2",
    "canonicalName": "PCSX2",
    "sourceType": "github_releases",
    "repository": "PCSX2/pcsx2",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_stenzek_duckstation",
    "displayName": "DuckStation",
    "canonicalName": "DuckStation",
    "sourceType": "github_releases",
    "repository": "stenzek/duckstation",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": false
  },
  {
    "sourceKey": "gh_cemu_project_cemu",
    "displayName": "Cemu",
    "canonicalName": "Cemu",
    "sourceType": "github_releases",
    "repository": "cemu-project/Cemu",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_mgba_emu_mgba",
    "displayName": "mGBA",
    "canonicalName": "mGBA",
    "sourceType": "github_releases",
    "repository": "mgba-emu/mgba",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_godotengine_godot",
    "displayName": "Godot Engine",
    "canonicalName": "Godot Engine",
    "sourceType": "github_releases",
    "repository": "godotengine/godot",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_mpv_player_mpv",
    "displayName": "mpv",
    "canonicalName": "mpv",
    "sourceType": "github_releases",
    "repository": "mpv-player/mpv",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_jellyfin_jellyfin",
    "displayName": "Jellyfin Server",
    "canonicalName": "Jellyfin Server",
    "sourceType": "github_releases",
    "repository": "jellyfin/jellyfin",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_jellyfin_jellyfin_media_player",
    "displayName": "Jellyfin Media Player",
    "canonicalName": "Jellyfin Media Player",
    "sourceType": "github_releases",
    "repository": "jellyfin/jellyfin-media-player",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_marktext_marktext",
    "displayName": "Marktext",
    "canonicalName": "Marktext",
    "sourceType": "github_releases",
    "repository": "marktext/marktext",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_zettlr_zettlr",
    "displayName": "Zettlr",
    "canonicalName": "Zettlr",
    "sourceType": "github_releases",
    "repository": "Zettlr/Zettlr",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_giuspen_cherrytree",
    "displayName": "CherryTree",
    "canonicalName": "CherryTree",
    "sourceType": "github_releases",
    "repository": "giuspen/cherrytree",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_minbrowser_min",
    "displayName": "Min browser",
    "canonicalName": "Min browser",
    "sourceType": "github_releases",
    "repository": "minbrowser/min",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gh_flameshot_org_flameshot",
    "displayName": "Flameshot",
    "canonicalName": "Flameshot",
    "sourceType": "github_releases",
    "repository": "flameshot-org/flameshot",
    "namePattern": "Flameshot",
    "publisherPattern": "flameshot",
    "deploymentMode": "winget_preferred",
    "wingetPackageId": "Flameshot.Flameshot",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gitlab_gimp",
    "displayName": "GIMP",
    "canonicalName": "GIMP",
    "sourceType": "vendor_text",
    "sourceUrl": "https://download.gimp.org/gimp/v3.2/windows/",
    "adapter": "gimp_windows_index",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gitlab_inkscape",
    "displayName": "Inkscape",
    "canonicalName": "Inkscape",
    "sourceType": "gitlab_releases",
    "sourceUrl": "https://gitlab.com/api/v4/projects/inkscape%2Finkscape/releases",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  },
  {
    "sourceKey": "gitlab_krita",
    "displayName": "Krita",
    "canonicalName": "Krita",
    "sourceType": "gitlab_releases",
    "sourceUrl": "https://invent.kde.org/api/v4/projects/graphics%2Fkrita/releases",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": false
  },
  {
    "sourceKey": "gitlab_digikam",
    "displayName": "digiKam",
    "canonicalName": "digiKam",
    "sourceType": "gitlab_releases",
    "sourceUrl": "https://invent.kde.org/api/v4/projects/graphics%2Fdigikam/releases",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": false
  },
  {
    "sourceKey": "gitlab_kdenlive",
    "displayName": "Kdenlive",
    "canonicalName": "Kdenlive",
    "sourceType": "gitlab_releases",
    "sourceUrl": "https://invent.kde.org/api/v4/projects/multimedia%2Fkdenlive/releases",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": false
  },
  {
    "sourceKey": "gitlab_meld",
    "displayName": "Meld",
    "canonicalName": "Meld",
    "sourceType": "gitlab_releases",
    "sourceUrl": "https://gitlab.gnome.org/api/v4/projects/GNOME%2Fmeld/releases",
    "deploymentMode": "intelligence_only",
    "pollMinutes": 60,
    "enabled": true
  }
]
