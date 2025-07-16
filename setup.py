"""
Setup script for Canonical SIEM Rule Converter.
"""

from setuptools import setup, find_packages

setup(
    name="canonical",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    install_requires=[
        "langgraph>=0.0.55",
        "chromadb>=0.4.18",
        "sentence-transformers>=2.2.2",
        "transformers>=4.35.0",
        "torch>=2.1.0",
        "qwen-agent>=0.0.3",
        "modelscope>=1.9.0",
        "pyyaml>=6.0.1",
        "ruamel.yaml>=0.17.32",
        "pandas>=2.1.0",
        "numpy>=1.24.0",
        "requests>=2.31.0",
        "fastapi>=0.104.0",
        "uvicorn>=0.24.0",
        "pydantic>=2.4.0",
        "pydantic-settings>=2.0.0",
        "loguru>=0.7.2",
        "python-dotenv>=1.0.0",
        "tqdm>=4.66.0",
        "gitpython>=3.1.40",
        "click>=8.1.0",
        "rank-bm25>=0.2.2",
        "pymupdf>=1.23.0",
        "mistralai>=0.1.0",
        "accelerate>=0.21.0",
    ],
    extras_require={
        "dev": [
            "jupyter>=1.0.0",
            "matplotlib>=3.7.0",
            "seaborn>=0.12.0",
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "canonical=canonical.cli:main",
        ],
    },
    author="Canonical Team",
    author_email="team@canonical.dev",
    description="Intelligent SIEM rule converter that transforms security rules between different formats",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/canonical/canonical",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
) 