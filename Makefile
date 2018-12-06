########################################################
# Makefile for FirewallP
#
# usage:
#   gmake sdist ---------------- produce a tarball
#   gmake srpm ----------------- produce a SRPM
#   gmake rpm  ----------------- produce RPMs
########################################################

# VARIABLE SECTION
NAME = firewallp
OS = $(shell uname -s)

PYTHON=python
SITELIB = $(shell $(PYTHON) -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")

# VERSION file provides one place to update the software version
VERSION := $(shell sed -rn 's/.*([0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9]+).*/\1/p' ${NAME}/__init__.py)
RELEASE := 1

# RPM build parameters
RPMSPECDIR= packaging/rpm
RPMSPEC = $(RPMSPECDIR)/firewallp.spec
RPMDIST = $(shell rpm --eval '%{?dist}')
RPMNVR = "$(NAME)-$(VERSION)$(RPMDIST)"
# -----------

.PHONY: all
all: clean python

.PHONY: clean
clean:
	@echo "Cleaning up distutils stuff"
	rm -rf build
	rm -rf dist
	rm -rf firewallp.egg-info/
	@echo "Cleaning up byte compiled python stuff"
	find . -type f -regex ".*\.py[co]$$" -delete
	find . -type d -name "__pycache__" -delete
	@echo "Cleaning up RPM building stuff"
	rm -rf MANIFEST rpm-build

.PHONY: python
python:
	$(PYTHON) setup.py build

.PHONY: install
install:
	$(PYTHON) setup.py install

.PHONY: sdist
sdist: clean
	$(PYTHON) setup.py sdist

.PHONY: rpmcommon
rpmcommon: sdist
	@mkdir -p rpm-build
	@cp dist/*.gz rpm-build/
	@cp firewallp.py rpm-build/firewallp
	@cp etc/firewallp/* rpm-build/
	@cp systemd/firewallp.service rpm-build/
	@sed -e 's#^Version:.*#Version: $(VERSION)#' $(RPMSPEC) >rpm-build/$(NAME).spec

.PHONY: srpm
srpm: rpmcommon
	@rpmbuild --define "_topdir %(pwd)/rpm-build" \
	--define "_builddir %{_topdir}" \
	--define "_rpmdir %{_topdir}" \
	--define "_srcrpmdir %{_topdir}" \
	--define "_specdir $(RPMSPECDIR)" \
	--define "_sourcedir %{_topdir}" \
	-bs rpm-build/$(NAME).spec
	@rm -f rpm-build/$(NAME).spec
	@echo "#############################################"
	@echo "FirewallP SRPM is built:"
	@echo "    rpm-build/$(RPMNVR).src.rpm"
	@echo "#############################################"

.PHONY: rpm
rpm: rpmcommon
	@rpmbuild --define "_topdir %(pwd)/rpm-build" \
	--define "_builddir %{_topdir}" \
	--define "_rpmdir %{_topdir}" \
	--define "_srcrpmdir %{_topdir}" \
	--define "_specdir $(RPMSPECDIR)" \
	--define "_sourcedir %{_topdir}" \
	--define "_rpmfilename %%{NAME}-%%{VERSION}.%%{ARCH}.rpm" \
	--define "__python `which $(PYTHON)`" \
	-ba rpm-build/$(NAME).spec
	@rm -f rpm-build/$(NAME).spec
	@echo "#############################################"
	@echo "FirewallP RPM is built:"
	@echo "    rpm-build/$(RPMNVR).noarch.rpm"
	@echo "#############################################"

version:
	@echo "Package version: $(VERSION)"
